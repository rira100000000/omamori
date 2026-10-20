# frozen_string_literal: true

# Runs the eval cases against an engine and scores how well each risk is detected.
# See evals/README.md.

require 'optparse'
require 'yaml'
require 'json'
require 'tmpdir'
require 'fileutils'
require 'open3'
require 'digest'
require_relative '../lib/omamori/core_runner'

module OmamoriEvals
  CASES_DIR = File.expand_path('cases', __dir__)
  RESULTS_DIR = File.expand_path('results', __dir__)
  REAL_DIR = File.expand_path('real', __dir__)
  # Code from other projects is fetched at eval time and kept out of git (their licenses differ from omamori's)
  REAL_CACHE_DIR = File.expand_path('.cache/real', __dir__)
  THRESHOLDS = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9].freeze
  RISKS = Omamori::AIAnalysisEngine::PromptManager::RISK_PROMPTS.keys

  # PromptManager only needs #get from its config
  PromptConfig = Struct.new(:values) do
    def get(key, default = nil)
      values.fetch(key, default)
    end
  end

  Case = Struct.new(:id, :path, :expected, :files, :diff)

  JUDGE_CACHE_DIR = File.expand_path('.cache/judge', __dir__)

  # Reuses the classifier's answer for the same model, code, and questions, so reruns cost nothing.
  # Use --no-cache when measuring run-to-run variation.
  class CachedClassifier
    def initialize(client, model)
      @client = client
      @model = model
    end

    def input_tokens
      @client.input_tokens
    end

    def classify(state, questions)
      path = File.join(JUDGE_CACHE_DIR, "#{Digest::SHA256.hexdigest([@model, state, questions.to_a].to_json)}.json")
      if File.exist?(path)
        return JSON.parse(File.read(path)).to_h { |name, probability| [name.to_sym, probability] }
      end

      answers = @client.classify(state, questions)
      # Errors are not cached, so they are retried next time
      unless answers.values.include?(nil)
        FileUtils.mkdir_p(JUDGE_CACHE_DIR)
        File.write(path, answers.to_json)
      end
      answers
    end
  end

  class Runner
    def initialize(options)
      @options = options
      @prompt_manager = Omamori::AIAnalysisEngine::PromptManager.new(PromptConfig.new({ 'language' => 'en' }))
      @diff_splitter = Omamori::AIAnalysisEngine::DiffSplitter.new
      # Same resolution as `omamori scan`, from the command-line options only
      config = options[:base_url] ? { 'classifier' => { 'provider' => options[:classifier], 'base_url' => options[:base_url] } } : {}
      overrides = options.slice(:classifier, :classifier_model, :reporter, :reporter_model,
                                :reporter_fallback, :reporter_fallback_model)
      @settings = Omamori::AISettings.new(PromptConfig.new(config), overrides)
      @llm_client = @settings.build_reporter_client
      @question_log = {}
      @reporter_calls = 0
      @reporter_unanswered = 0
      @reporter_calls_mutex = Mutex.new
      @question_log_mutex = Mutex.new
    end

    def run
      cases = load_cases
      abort 'No cases found.' if cases.empty?
      cases.each { |c| c.diff = build_diff(c) }
      puts "#{setup} / cases: #{cases.size} / runs: #{@options[:runs]}"

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
      return load_real_cases if @options[:real]

      Dir[File.join(@options[:cases_dir] || CASES_DIR, '**', '*.yml')].sort.filter_map do |path|
        data = YAML.safe_load_file(path)
        next if @options[:case] && !data.fetch('id').include?(@options[:case])

        expected = data.fetch('expected').transform_keys(&:to_sym)
        if @options[:risk]
          next unless expected.key?(@options[:risk])

          expected = expected.slice(@options[:risk])
        end

        Case.new(data.fetch('id'), path, expected, data.fetch('files'))
      end
    end

    # Real security fixes from evals/real/manifest.yml. Each fix gives two cases: the fix reversed
    # (introduces the vulnerability) and the fix itself (touches the same code safely).
    def load_real_cases
      entries = YAML.safe_load_file(File.join(REAL_DIR, 'manifest.yml')).fetch('entries')
      entries = entries.select { |e| e['risk'] == @options[:risk].to_s } if @options[:risk]
      entries = entries.select { |e| e['kind'] == @options[:kind] } if @options[:kind]
      entries = entries.select { |e| real_split(e['id']) == @options[:split] } if @options[:split]
      excluded = real_exclusions
      entries.flat_map do |entry|
        fixed = entry['files'].to_h { |path| [path, fetch_file(entry['repo'], entry['commit'], path)] }
        vulnerable = entry['files'].to_h { |path| [path, fetch_file(entry['repo'], entry['parent'], path)] }
        risk = entry['risk'].to_sym
        [
          Case.new("#{entry['id']}-reversed", entry['advisory'], { risk => true },
                   entry['files'].map { |path| { 'path' => path, 'before' => fixed[path], 'after' => vulnerable[path] } }),
          Case.new("#{entry['id']}-fix", entry['advisory'], { risk => false },
                   entry['files'].map { |path| { 'path' => path, 'before' => vulnerable[path], 'after' => fixed[path] } })
        ].reject { |c| excluded.include?(c.id) }
         .select { |c| @options[:case].nil? || c.id.include?(@options[:case]) }
      end
    end

    # Cases that the manual review (evals/real/review.yml) found unusable: a mislabeled or non-substantive fix
    # (C, D) drops both of its cases; a fix that is itself incomplete (E) drops its "safe" case.
    def real_exclusions
      path = File.join(REAL_DIR, 'review.yml')
      return [] if @options[:no_review] || !File.exist?(path)

      YAML.safe_load_file(path).fetch('reviews').flat_map do |review|
        base = review['case'].sub(/-(reversed|fix)\z/, '')
        case review['category']
        when 'C', 'D' then ["#{base}-reversed", "#{base}-fix"]
        when 'E' then ["#{base}-fix"]
        else []
        end
      end
    end

    # A fixed half of the real fixes is used for tuning and the other half only for checking
    def real_split(id)
      Digest::SHA256.hexdigest(id).to_i(16).even? ? 'tune' : 'holdout'
    end

    def fetch_file(repo, sha, path)
      cache = File.join(REAL_CACHE_DIR, repo, sha, path)
      return File.read(cache) if File.exist?(cache)

      content, status = Open3.capture2('gh', 'api', '-H', 'Accept: application/vnd.github.raw',
                                       "/repos/#{repo}/contents/#{path}?ref=#{sha}")
      raise "Could not fetch #{repo}@#{sha}:#{path}" unless status.success?

      FileUtils.mkdir_p(File.dirname(cache))
      File.write(cache, content)
      content
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
      # Only the labeled risks are scored, so only their questions are sent unless --all-risks
      risks = @options[:all_risks] ? RISKS : eval_case.expected.keys
      classified = scanner.classify_units(units, risks)
      record_questions(eval_case, classified)
      probabilities = risks.to_h do |risk|
        per_file = classified.map { |_chunk, result| result[risk] }
        [risk, per_file.include?(nil) ? nil : per_file.max]
      end
      @options[:pipeline] ? apply_reporter(eval_case, classified, probabilities) : probabilities
    end

    # Pipeline mode: for each labeled risk the classifier flagged, ask the reporter as `omamori scan` does.
    # The final answer is 1.0 when the reporter reports something (or could not answer), 0.0 when it finds nothing.
    def apply_reporter(eval_case, classified, probabilities)
      eval_case.expected.each_key do |risk|
        flagged = classified.select { |_chunk, result, _triggers| scanner.flagged?(result[risk]) }
        next probabilities[risk] = 0.0 if flagged.empty?

        reports = flagged.map { |chunk, result, triggers| scanner.report(chunk, risk, result[risk], triggers[risk]) }
        reported = reports.any?(&:any?)
        unanswered = reports.flatten.count { |r| r['unreported'] }
        @reporter_calls_mutex.synchronize do
          @reporter_calls += flagged.size
          @reporter_unanswered += unanswered
        end
        probabilities[risk] = reported ? 1.0 : 0.0
      end
      probabilities
    end

    # Keeps every question's probability for the labeled risks (highest across files), to see which sub-checks fire
    def record_questions(eval_case, classified)
      answers = classified.map(&:last).reduce({}) do |merged, file_answers|
        merged.merge(file_answers) { |_name, a, b| a && b ? [a, b].max : nil }
      end
      labeled = answers.select { |name, _| eval_case.expected.key?(Omamori::AIAnalysisEngine::PromptManager.risk_of(name)) }
      @question_log_mutex.synchronize { (@question_log[eval_case.id] ||= []) << labeled }
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
      @scanner ||= Omamori::AIAnalysisEngine::ChecklistScanner.new(
        decision_client: decision_client, llm_client: @llm_client, prompt_manager: @prompt_manager,
        diff_splitter: @diff_splitter, json_schema: Omamori::CoreRunner::JSON_SCHEMA, model: @settings.reporter_model,
        threshold: @options[:threshold],
        concurrency: 1, # cases are already run in parallel
        sub_checks: @options[:sub_checks]
      )
    end

    def setup
      return @settings.describe unless @settings.classifier?

      "#{@settings.describe}, sub-checks: #{@options[:sub_checks] ? 'on' : 'off'}" \
        "#{@options[:pipeline] ? ", pipeline at threshold #{@options[:threshold]}" : ''}"
    end

    def decision_client
      @decision_client ||= begin
        client = @settings.build_classifier_client
        client && @options[:cache] ? CachedClassifier.new(client, @settings.classifier['model']) : client
      end
    end

    # Scores every labeled (case, risk) pair in every run
    def build_report(cases, runs, elapsed)
      pairs = cases.flat_map { |c| c.expected.map { |risk, expected| [c, risk, expected] } }
      threshold = @options[:threshold]

      {
        setup: setup,
        classifier_input_tokens: decision_client&.input_tokens,
        reporter_calls: @options[:pipeline] ? @reporter_calls : nil,
        reporter_unanswered: @options[:pipeline] ? @reporter_unanswered : nil,
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
      if report[:reporter_calls]
        puts "Reporter calls: #{report[:reporter_calls]} (unanswered, kept as flags: #{report[:reporter_unanswered]})"
      end
      if report[:classifier_input_tokens]
        per_case = report[:classifier_input_tokens] / (report[:cases] * report[:runs])
        puts "Classifier input tokens: #{report[:classifier_input_tokens]} (#{per_case} per case)"
      end
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
      File.write(path, JSON.pretty_generate(report.merge(raw: raw, questions: @question_log)))
      puts "Saved: #{path}"
    end
  end
end

options = { classifier: 'typesafe', sub_checks: true, cache: true, runs: 1, concurrency: 8,
            threshold: Omamori::AISettings::DEFAULT_THRESHOLD }
OptionParser.new do |opts|
  opts.banner = 'Usage: ruby evals/run.rb [options]'
  opts.on('--classifier PROVIDER', 'typesafe (default), openai, ollama, or none (baseline: the reporter checks everything)') do |v|
    options[:classifier] = v
  end
  opts.on('--classifier-model MODEL', 'e.g. jev-1.13.0, gpt-6-luna') { |v| options[:classifier_model] = v }
  opts.on('--pipeline', 'Also run the reporter on flagged checks and score its final answer (uses --threshold)') do
    options[:pipeline] = true
  end
  opts.on('--[no-]cache', 'Reuse cached classifier answers (default on; turn off to measure variation)') do |v|
    options[:cache] = v
  end
  opts.on('--all-risks', 'Ask every risk for every case, not only the labeled ones') { options[:all_risks] = true }
  opts.on('--[no-]sub-checks', 'Also ask each risk as concrete sub-checks (default on)') { |v| options[:sub_checks] = v }
  opts.on('--base-url URL', 'Server for the classifier provider (e.g. a local SystemOne server)') { |v| options[:base_url] = v }
  opts.on('--reporter PROVIDER', 'Reporter for --classifier none: a RubyLLM provider, claude_code, or codex') do |v|
    options[:reporter] = v
  end
  opts.on('--reporter-model MODEL', 'e.g. gemini-3.8-flash, claude-sonnet-5-5, sonnet') { |v| options[:reporter_model] = v }
  opts.on('--reporter-fallback PROVIDER', 'Reporter asked when the reporter refuses or fails') do |v|
    options[:reporter_fallback] = v
  end
  opts.on('--reporter-fallback-model MODEL', 'Model for --reporter-fallback') { |v| options[:reporter_fallback_model] = v }
  opts.on('--runs N', Integer, 'Run every case N times (default 1)') { |v| options[:runs] = v }
  opts.on('--risk RISK', 'Only cases labeled with this risk') { |v| options[:risk] = v.to_sym }
  opts.on('--case TEXT', 'Only cases whose id contains TEXT') { |v| options[:case] = v }
  opts.on('--real', 'Use real security fixes from evals/real/manifest.yml (fetched with the gh CLI)') do
    options[:real] = true
  end
  opts.on('--no-review', 'With --real, keep the cases the manual review excluded') { options[:no_review] = true }
  opts.on('--split SPLIT', %w[tune holdout], 'With --real, only the tuning half or only the held-out half') do |v|
    options[:split] = v
  end
  opts.on('--kind KIND', %w[app library], 'With --real, only application code or only library code') do |v|
    options[:kind] = v
  end
  opts.on('--holdout', 'Use the held-out cases in evals/holdout/ (never used for tuning)') do
    options[:cases_dir] = File.expand_path('holdout', __dir__)
  end
  opts.on('--threshold T', Float, 'Threshold for the per-risk table (default 0.3)') { |v| options[:threshold] = v }
  opts.on('--concurrency N', Integer, 'Cases run in parallel (default 8)') { |v| options[:concurrency] = v }
end.parse!

if options[:runs] > 1 && options[:cache]
  warn 'Running more than once: the classifier cache is turned off so each run is a fresh answer.'
  options[:cache] = false
end

begin
  OmamoriEvals::Runner.new(options).run
rescue Omamori::AISettings::Error => e
  abort "Configuration error: #{e.message}"
end
