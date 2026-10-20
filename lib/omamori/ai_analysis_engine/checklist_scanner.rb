# frozen_string_literal: true

require_relative '../parallel'

module Omamori
  module AIAnalysisEngine
    # Runs each risk as an independent yes/no check with a fast decision model,
    # then asks an LLM to write a report only for the checks that did not pass.
    class ChecklistScanner
      DEFAULT_THRESHOLD = 0.3
      DEFAULT_CONCURRENCY = 8

      Unit = Struct.new(:label, :content)

      # Other risks get their own report, so each report sticks to its one risk to avoid duplicates
      SINGLE_RISK_INSTRUCTION = "\nReport only the vulnerability type described above. " \
                                "If the code does not have it, return an empty list.\n"

      def initialize(decision_client:, llm_client:, prompt_manager:, diff_splitter:, json_schema:, model:,
                     threshold: DEFAULT_THRESHOLD, concurrency: DEFAULT_CONCURRENCY, report_concurrency: concurrency,
                     sub_checks: true)
        @decision_client = decision_client
        @llm_client = llm_client
        @prompt_manager = prompt_manager
        @diff_splitter = diff_splitter
        @json_schema = json_schema
        @model = model
        @threshold = threshold
        @concurrency = concurrency
        @report_concurrency = report_concurrency
        @sub_checks = sub_checks
      end

      # units: [[label, content], ...] (a file path and its diff or source)
      def scan(units, risks_to_check)
        puts "Checking #{units.size} file(s) x #{risks_to_check.size} checks..."
        classified = classify_units(units, risks_to_check)
        total = classified.sum { |_chunk, probabilities| probabilities.size }

        flagged = classified.flat_map do |chunk, probabilities, triggers|
          probabilities.filter_map do |risk, probability|
            [chunk, risk, probability, triggers[risk]] if flagged?(probability)
          end
        end
        puts "#{flagged.size} check(s) flagged, #{total - flagged.size} passed."

        risks = Parallel.map(flagged, @report_concurrency) do |chunk, risk, probability, risk_triggers|
          report(chunk, risk, probability, risk_triggers)
        end
        { 'security_risks' => risks.flatten }
      end

      # Each risk is asked as an overall question plus its sub-checks; the risk's probability is the highest of them.
      # Returns [[chunk, { risk => probability or nil }, { risk => [sub-check names at or above the threshold] },
      #   { question name => probability }], ...]
      def classify_units(units, risks_to_check)
        chunks = expand(units)
        questions = risks_to_check.map { |risk| @prompt_manager.build_questions(risk, sub_checks: @sub_checks) }
                                  .reduce({}, :merge)
        parallel_map(chunks) do |chunk|
          answers = classify(chunk, questions)
          [chunk, aggregate(answers, risks_to_check), triggers(answers), answers]
        end
      end

      # Asks the reporter to write a report for one flagged risk. Returns the reported risks (empty when the reporter
      # finds nothing; a review note when the reporter could not answer).
      def report(chunk, risk, probability, risk_triggers = [])
        puts "Reporting #{risk} in #{chunk.label} (p=#{probability ? format('%.2f', probability) : 'n/a'})..."
        prompt = @prompt_manager.build_prompt(chunk.content, [risk], @json_schema, file_path: chunk.label) +
                 SINGLE_RISK_INSTRUCTION + trigger_hint(risk_triggers)
        result = @llm_client.analyze(prompt, @json_schema, model: @model)
        result ? result.fetch('security_risks', []) : [unreported_flag(chunk, risk, probability)]
      end

      def flagged?(probability)
        probability.nil? || probability >= @threshold
      end

      private

      def expand(units)
        units.flat_map do |label, content|
          parts = @diff_splitter.split(content)
          parts.each_with_index.map do |part, index|
            Unit.new(parts.size > 1 ? "#{label} (chunk #{index + 1}/#{parts.size})" : label, part)
          end
        end
      end

      def classify(chunk, questions)
        @decision_client.classify(chunk.content, questions)
      rescue StandardError => e
        # If the classifier fails, every check is escalated so nothing is silently skipped
        puts "Decision API error for #{chunk.label}: #{e.message}"
        questions.keys.to_h { |risk| [risk, nil] }
      end

      # nil (no answer) wins, so a risk with any unanswered question is escalated
      def aggregate(answers, risks)
        by_risk = answers.group_by { |name, _| PromptManager.risk_of(name) }
        risks.to_h do |risk|
          probabilities = by_risk.fetch(risk, []).map(&:last)
          [risk, probabilities.empty? || probabilities.include?(nil) ? nil : probabilities.max]
        end
      end

      def triggers(answers)
        answers.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |(name, probability), result|
          next unless name.to_s.include?(PromptManager::SUB_CHECK_SEPARATOR) && probability && probability >= @threshold

          result[PromptManager.risk_of(name)] << name
        end
      end


      # Tells the reporter which concrete patterns the classifier matched, so it checks those first
      def trigger_hint(risk_triggers)
        texts = Array(risk_triggers).filter_map { |name| @prompt_manager.sub_check_text(name) }
        return '' if texts.empty?

        "A classifier flagged these patterns in the code. Check each of them carefully:\n" +
          texts.map { |text| "- #{text}\n" }.join
      end

      # Keeps the classifier's flag when the LLM could not write a report, so the finding is not lost
      def unreported_flag(chunk, risk, probability)
        {
          'type' => risk.to_s,
          'location' => chunk.label,
          'details' => "Flagged by the decision model (p=#{probability ? format('%.2f', probability) : 'n/a'}), " \
                       'but the LLM could not write a report. Review this change manually.',
          'severity' => 'Info',
          'unreported' => true
        }
      end

      def parallel_map(items, &)
        Parallel.map(items, @concurrency, &)
      end
    end
  end
end
