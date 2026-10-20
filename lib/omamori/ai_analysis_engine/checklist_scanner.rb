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
                     threshold: DEFAULT_THRESHOLD, concurrency: DEFAULT_CONCURRENCY, report_concurrency: concurrency)
        @decision_client = decision_client
        @llm_client = llm_client
        @prompt_manager = prompt_manager
        @diff_splitter = diff_splitter
        @json_schema = json_schema
        @model = model
        @threshold = threshold
        @concurrency = concurrency
        @report_concurrency = report_concurrency
      end

      # units: [[label, content], ...] (a file path and its diff or source)
      def scan(units, risks_to_check)
        puts "Checking #{units.size} file(s) x #{risks_to_check.size} checks..."
        classified = classify_units(units, risks_to_check)
        total = classified.sum { |_chunk, probabilities| probabilities.size }

        flagged = classified.flat_map do |chunk, probabilities|
          probabilities.filter_map { |risk, probability| [chunk, risk, probability] if flagged?(probability) }
        end
        puts "#{flagged.size} check(s) flagged, #{total - flagged.size} passed."

        risks = Parallel.map(flagged, @report_concurrency) { |chunk, risk, probability| report(chunk, risk, probability) }
        { 'security_risks' => risks.flatten }
      end

      # Returns [[chunk, { risk => probability or nil }], ...]
      def classify_units(units, risks_to_check)
        chunks = expand(units)
        questions = risks_to_check.to_h { |risk| [risk, @prompt_manager.build_question(risk)] }
        parallel_map(chunks) { |chunk| [chunk, classify(chunk, questions)] }
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

      def flagged?(probability)
        probability.nil? || probability >= @threshold
      end

      def report(chunk, risk, probability)
        puts "Reporting #{risk} in #{chunk.label} (p=#{probability ? format('%.2f', probability) : 'n/a'})..."
        prompt = @prompt_manager.build_prompt(chunk.content, [risk], @json_schema, file_path: chunk.label) +
                 SINGLE_RISK_INSTRUCTION
        result = @llm_client.analyze(prompt, @json_schema, model: @model)
        result ? result.fetch('security_risks', []) : [unreported_flag(chunk, risk, probability)]
      end

      # Keeps the classifier's flag when the LLM could not write a report, so the finding is not lost
      def unreported_flag(chunk, risk, probability)
        {
          'type' => risk.to_s,
          'location' => chunk.label,
          'details' => "Flagged by the decision model (p=#{probability ? format('%.2f', probability) : 'n/a'}), " \
                       'but the LLM could not write a report. Review this change manually.',
          'severity' => 'Info'
        }
      end

      def parallel_map(items, &)
        Parallel.map(items, @concurrency, &)
      end
    end
  end
end
