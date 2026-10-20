# frozen_string_literal: true

# Runs the eval cases against an engine and scores how well each risk is detected.
# See evals/README.md.

require 'optparse'
require 'yaml'
require 'json'
require 'tmpdir'
require 'fileutils'
require 'open3'
require_relative '../lib/omamori/core_runner'

module OmamoriEvals
  CASES_DIR = File.expand_path('cases', __dir__)
  RESULTS_DIR = File.expand_path('results', __dir__)
  THRESHOLDS = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9].freeze
  RISKS = Omamori::AIAnalysisEngine::PromptManager::RISK_PROMPTS.keys

  # PromptManager only needs #get from its config
  PromptConfig = Struct.new(:values) do
    def get(key, default = nil)
      values.fetch(key, default)
    end
  end

  Case = Struct.new(:id, :path, :expected, :files, :diff)

  class Runner
    def initialize(options)
      @options = options
      @prompt_manager = Omamori::AIAnalysisEngine::PromptManager.new(PromptConfig.new({ 'language' => 'en' }))
      @diff_splitter = Omamori::AIAnalysisEngine::DiffSplitter.new
      # Same resolution as `omamori scan`, from the command-line options only
      config = options[:base_url] ? { 'classifier' => { 'provider' => options[:classifier], 'base_url' => options[:base_url] } } : {}
      @settings = Omamori::AISettings.new(PromptConfig.new(config), options.slice(:classifier, :classifier_model,
                                                                                  :reporter, :reporter_model))
      @llm_client = @settings.build_reporter_client
    end

    def run
      cases = load_cases
      abort 'No cases found.' if cases.empty?
      cases.each { |c| c.diff = build_diff(c) }
      puts "#{@settings.describe} / cases: #{cases.size} / runs: #{@options[:runs]}"

      started = Time.now
      runs = Array.new(@options[:runs]) do |run_index|
        puts "Run #{run_index + 1}/#{@options[:runs]}..."
        Omamori::Parallel.map(cases, @options[:concurrency]) { |c| [c.id, evaluate(c)] }.to_h
      end
      elapsed = Time.now - started

      report = build_report(cases, runs, elapsed)
      print_report(report)
      save(report, cases, runs)
    end

    private

    def load_cases
      Dir[File.join(CASES_DIR, '**', '*.yml')].sort.filter_map do |path|
        data = YAML.safe_load_file(path)
        expected = data.fetch('expected').transform_keys(&:to_sym)
        if @options[:risk]
          next unless expected.key?(@options[:risk])

          expected = expected.slice(@options[:risk])
        end

        Case.new(data.fetch('id'), path, expected, data.fetch('files'))
      end
    end

    # Commits the before files in a throwaway repo, writes the after files, and returns the diff
    def build_diff(eval_case)
      Dir.mktmpdir('omamori-eval') do |dir|
        git(dir, 'init', '-q')
        eval_case.files.each { |f| write(dir, f['path'], f['before']) if f['before'] }
        git(dir, 'add', '-A')
        git(dir, '-c', 'user.name=eval', '-c', 'user.email=eval@example.com', 'commit', '-q', '--allow-empty', '-m', 'before')
        eval_case.files.each { |f| write(dir, f['path'], f['after']) }
        git(dir, 'add', '-A')
        git(dir, 'diff', '--cached')
      end
    end

    def write(dir, path, content)
      full_path = File.join(dir, path)
      FileUtils.mkdir_p(File.dirname(full_path))
      File.write(full_path, content)
    end

    def git(dir, *args)
      out, status = Open3.capture2e('git', '-C', dir, *args)
      raise "git #{args.join(' ')} failed: #{out}" unless status.success?

      out
    end

    # Returns { risk => probability or nil (error) } for every risk
    def evaluate(eval_case)
      @settings.classifier? ? evaluate_with_decision_model(eval_case) : evaluate_with_llm(eval_case)
    end

    # Same path as `omamori scan` with a classifier: per-file units, all risks per unit.
    # A case's probability for a risk is the highest among its files.
    def evaluate_with_decision_model(eval_case)
      units = @diff_splitter.split_by_file(eval_case.diff)
      classified = scanner.classify_units(units, RISKS)
      RISKS.to_h do |risk|
        probabilities = classified.map { |_chunk, result| result[risk] }
        [risk, probabilities.include?(nil) ? nil : probabilities.max]
      end
    end

    # Baseline: the reporter checks all risks in one prompt, as `omamori scan --classifier none` does.
    # The risk type is constrained to the risk keys so answers can be scored.
    def evaluate_with_llm(eval_case)
      prompt = @prompt_manager.build_prompt(eval_case.diff, RISKS, llm_schema)
      result = @llm_client.analyze(prompt, llm_schema, model: @settings.reporter_model)
      return RISKS.to_h { |risk| [risk, nil] } unless result

      found = result['security_risks'].map { |r| r['type'].to_s.to_sym }
      RISKS.to_h { |risk| [risk, found.include?(risk) ? 1.0 : 0.0] }
    end

    def llm_schema
      @llm_schema ||= begin
        schema = JSON.parse(Omamori::CoreRunner::JSON_SCHEMA.to_json)
        schema['properties']['security_risks']['items']['properties']['type'] = { 'type' => 'string', 'enum' => RISKS.map(&:to_s) }
        schema
      end
    end

    def scanner
      Omamori::AIAnalysisEngine::ChecklistScanner.new(
        decision_client: decision_client, llm_client: @llm_client, prompt_manager: @prompt_manager,
        diff_splitter: @diff_splitter, json_schema: Omamori::CoreRunner::JSON_SCHEMA, model: @settings.reporter_model,
        concurrency: 1 # cases are already run in parallel
      )
    end

    def decision_client
      @decision_client ||= @settings.build_classifier_client
    end

    # Scores every labeled (case, risk) pair in every run
    def build_report(cases, runs, elapsed)
      pairs = cases.flat_map { |c| c.expected.map { |risk, expected| [c, risk, expected] } }
      threshold = @options[:threshold]

      {
        setup: @settings.describe,
        runs: runs.size, cases: cases.size,
        elapsed_seconds: elapsed.round(1),
        errors: runs.sum { |run| run.values.sum { |probs| probs.values.count(&:nil?) } },
        sweep: THRESHOLDS.map { |t| score(pairs, runs, t).merge(threshold: t) },
        threshold: threshold,
        per_risk: RISKS.filter_map do |risk|
          risk_pairs = pairs.select { |_c, r, _e| r == risk }
          score(risk_pairs, runs, threshold).merge(risk: risk) unless risk_pairs.empty?
        end,
        mistakes: mistakes(pairs, runs, threshold),
        unlabeled_flags_per_case: unlabeled_flags(cases, runs, threshold)
      }
    end

    def score(pairs, runs, threshold)
      counts = Hash.new(0)
      runs.each do |run|
        pairs.each do |c, risk, expected|
          flagged = flagged?(run.dig(c.id, risk), threshold)
          counts[if expected
                   flagged ? :tp : :fn
                 else
                   flagged ? :fp : :tn
                 end] += 1
        end
      end
      counts.merge(recall: ratio(counts[:tp], counts[:tp] + counts[:fn]),
                   specificity: ratio(counts[:tn], counts[:tn] + counts[:fp]))
    end

    # A failed check is escalated to Gemini in omamori, so it counts as flagged
    def flagged?(probability, threshold)
      probability.nil? || probability >= threshold
    end

    def ratio(numerator, denominator)
      denominator.zero? ? nil : (numerator.to_f / denominator).round(3)
    end

    def mistakes(pairs, runs, threshold)
      pairs.filter_map do |c, risk, expected|
        probabilities = runs.map { |run| run.dig(c.id, risk) }
        wrong = probabilities.count { |p| flagged?(p, threshold) != expected }
        next if wrong.zero?

        { case: c.id, risk: risk, expected: expected, wrong_runs: wrong, probabilities: probabilities }
      end
    end

    # How many unlabeled checks per case would still be sent to Gemini for a report (cost and noise)
    def unlabeled_flags(cases, runs, threshold)
      total = runs.sum do |run|
        cases.sum { |c| run[c.id].count { |risk, p| !c.expected.key?(risk) && flagged?(p, threshold) } }
      end
      (total.to_f / (cases.size * runs.size)).round(2)
    end

    def print_report(report)
      puts
      puts "== #{report[:setup]} (#{report[:cases]} cases x #{report[:runs]} runs, #{report[:elapsed_seconds]}s, errors: #{report[:errors]})"
      puts
      puts 'threshold  recall  specificity   TP   FN   FP   TN'
      report[:sweep].each do |s|
        puts format('%9.1f  %6s  %11s %4d %4d %4d %4d', s[:threshold], s[:recall], s[:specificity],
                    s[:tp], s[:fn], s[:fp], s[:tn])
      end
      puts
      puts "Per risk at threshold #{report[:threshold]}:"
      report[:per_risk].each do |s|
        puts format('  %-38s recall %-6s specificity %-6s', s[:risk], s[:recall], s[:specificity])
      end
      puts
      puts "Mistakes at threshold #{report[:threshold]}:"
      report[:mistakes].each do |m|
        probabilities = m[:probabilities].map { |p| p ? format('%.2f', p) : 'err' }.join(' ')
        puts "  #{m[:case]} (#{m[:risk]}, expected #{m[:expected]}): #{m[:wrong_runs]}/#{report[:runs]} wrong [#{probabilities}]"
      end
      puts
      puts "Unlabeled checks flagged per case: #{report[:unlabeled_flags_per_case]}"
    end

    def save(report, cases, runs)
      FileUtils.mkdir_p(RESULTS_DIR)
      name = @settings.classifier? ? @settings.classifier['provider'] : "llm-#{@settings.reporter['provider'] || 'auto'}"
      path = File.join(RESULTS_DIR, "#{name}-#{Time.now.strftime('%Y%m%d-%H%M%S')}.json")
      raw = cases.to_h { |c| [c.id, runs.map { |run| run[c.id] }] }
      File.write(path, JSON.pretty_generate(report.merge(raw: raw)))
      puts "Saved: #{path}"
    end
  end
end

options = { classifier: 'typesafe', runs: 1, concurrency: 8,
            threshold: Omamori::AISettings::DEFAULT_THRESHOLD }
OptionParser.new do |opts|
  opts.banner = 'Usage: ruby evals/run.rb [options]'
  opts.on('--classifier PROVIDER', 'typesafe (default), openai, ollama, or none (baseline: the reporter checks everything)') do |v|
    options[:classifier] = v
  end
  opts.on('--classifier-model MODEL', 'e.g. jev-1.13.0, gpt-6-luna') { |v| options[:classifier_model] = v }
  opts.on('--base-url URL', 'Server for the classifier provider (e.g. a local SystemOne server)') { |v| options[:base_url] = v }
  opts.on('--reporter PROVIDER', 'Reporter for --classifier none: a RubyLLM provider, claude_code, or codex') do |v|
    options[:reporter] = v
  end
  opts.on('--reporter-model MODEL', 'e.g. gemini-3.8-flash, claude-sonnet-5-5, sonnet') { |v| options[:reporter_model] = v }
  opts.on('--runs N', Integer, 'Run every case N times (default 1)') { |v| options[:runs] = v }
  opts.on('--risk RISK', 'Only cases labeled with this risk') { |v| options[:risk] = v.to_sym }
  opts.on('--threshold T', Float, 'Threshold for the per-risk table (default 0.3)') { |v| options[:threshold] = v }
  opts.on('--concurrency N', Integer, 'Cases run in parallel (default 8)') { |v| options[:concurrency] = v }
end.parse!

begin
  OmamoriEvals::Runner.new(options).run
rescue Omamori::AISettings::Error => e
  abort "Configuration error: #{e.message}"
end
