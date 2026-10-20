# frozen_string_literal: true

require 'optparse'
require 'fileutils' # FileUtils を require する
require 'pathname'  # Pathname を require する
require 'shellwords'
require_relative 'ai_analysis_engine/llm_client'
require_relative 'ai_settings'
require_relative 'ai_analysis_engine/prompt_manager'
require_relative 'ai_analysis_engine/diff_splitter'
require_relative 'ai_analysis_engine/checklist_scanner'
require_relative 'report_generator/console_formatter'
require_relative 'report_generator/html_formatter'
require_relative 'report_generator/json_formatter'
require_relative 'static_analysers/brakeman_runner'
require_relative 'static_analysers/bundler_audit_runner'
require 'json'
require_relative 'config'

module Omamori
  class CoreRunner
    # Define the JSON Schema for Structured Output
    JSON_SCHEMA = {
      "type": 'object',
      "properties": {
        "security_risks": {
          "type": 'array',
          "description": '検出されたセキュリティリスクのリスト。',
          "items": {
            "type": 'object',
            "properties": {
              "type": {
                "type": 'string',
                "description": '検出されたリスクの種類 (例: XSS, CSRF, IDORなど)。3.3の診断対象脆弱性リストのいずれかであること。'
              },
              "location": {
                "type": 'string',
                "description": 'リスクが存在するコードのファイル名、行番号、またはコードスニペット。差分分析の場合は差分の該当箇所を示す形式 (例: ファイル名:+行番号) であること。'
              },
              "details": {
                "type": 'string',
                "description": 'リスクの詳細な説明と、なぜそれがリスクなのかの理由。'
              },
              "severity": {
                "type": 'string',
                "description": 'リスクの深刻度。',
                "enum": %w[Critical High Medium Low Info]
              },
              "code_snippet": {
                "type": 'string',
                "description": '該当するコードスニペット。'
              }
            },
            "required": %w[type location details severity]
          }
        }
      },
      "required": ['security_risks']
    }.freeze # Freeze the hash to make it immutable

    # Default risks to check, can be overridden by config
    DEFAULT_RISKS_TO_CHECK = [
      :xss, :sql_injection, :csrf, :idor, :mass_assignment, :open_redirect, :ssrf, :session_fixation
      # TODO: Add other risks from requirements based on PromptManager::RISK_PROMPTS.keys
    ].freeze

    DEFAULT_MODEL = AIAnalysisEngine::LLMClient::DEFAULT_MODEL

    # Threshold for splitting large content (characters as a proxy for tokens)
    # Can be overridden by config
    DEFAULT_SPLIT_THRESHOLD = 8000 # Characters

    def initialize(args)
      @args = args
      @options = { command: :scan, format: :console } # Default command and format
      @target_paths = []
      @config = Omamori::Config.new

      # Initialize components with configuration
      @prompt_manager = AIAnalysisEngine::PromptManager.new(@config)

      chunk_size = @config.get('chunk_size', DEFAULT_SPLIT_THRESHOLD)
      @diff_splitter = AIAnalysisEngine::DiffSplitter.new(chunk_size: chunk_size)

      report_config = @config.get('report', {})
      report_output_path = report_config.fetch('output_path', './omamori_report')
      html_template_path = report_config.fetch('html_template', nil)

      @console_formatter = ReportGenerator::ConsoleFormatter.new
      @html_formatter = ReportGenerator::HTMLFormatter.new(report_output_path, html_template_path)
      @json_formatter = ReportGenerator::JSONFormatter.new(report_output_path)

      static_analyser_config = @config.get('static_analysers', {})
      brakeman_options = static_analyser_config.fetch('brakeman', {}).fetch('options', {})
      bundler_audit_options = static_analyser_config.fetch('bundler_audit', {}).fetch('options', {})
      @brakeman_runner = StaticAnalysers::BrakemanRunner.new(brakeman_options)
      @bundler_audit_runner = StaticAnalysers::BundlerAuditRunner.new(bundler_audit_options)
    end

    def run
      parse_options

      case @options[:command]
      when :scan
        validate_ai_settings
        # Initialize results
        ai_analysis_result = { 'security_risks' => [] }
        brakeman_result = nil
        bundler_audit_result = nil

        # Run static analysers first unless --ai option is specified
        unless @options[:only_ai]
          puts 'Running static analysers...'
          brakeman_result = @brakeman_runner.run
          bundler_audit_result = @bundler_audit_runner.run
        end

        # Perform AI analysis based on scan mode
        case @options[:scan_mode]
        when :paths
          # Scan specified files/directories
          if @target_paths.empty?
            puts 'No paths specified for scan. Use --diff, --all, or provide paths.'
          else
            puts 'Scanning specified paths with AI...'
            ignore_patterns = @config.ignore_patterns
            force_scan_ignored = @options.fetch(:force_scan_ignored, false)
            files_to_scan = collect_files_from_paths(@target_paths, ignore_patterns, force_scan_ignored)

            if files_to_scan.empty?
              puts 'No Ruby files found in the specified paths.'
            elsif decision_engine?
              ai_analysis_result = checklist_scanner.scan(read_units(files_to_scan), get_risks_to_check)
            else
              files_to_scan.each do |file_path|
                file_content = File.read(file_path)
                puts "Analyzing file: #{file_path}..." # スキャン中のファイルパスを表示
                current_risks_to_check = get_risks_to_check
                # @diff_splitterのインスタンス変数 @chunk_size を参照して比較
                if file_content.length > @diff_splitter.instance_variable_get(:@chunk_size)
                  puts "File content exceeds threshold (#{@diff_splitter.instance_variable_get(:@chunk_size)} chars), splitting..."
                  file_ai_result = @diff_splitter.process_in_chunks(file_content, llm_client, JSON_SCHEMA,
                                                                    @prompt_manager, current_risks_to_check, file_path: file_path, model: llm_model)
                else
                  prompt = @prompt_manager.build_prompt(file_content, current_risks_to_check, JSON_SCHEMA,
                                                        file_path: file_path)
                  file_ai_result = llm_client.analyze(prompt, JSON_SCHEMA,
                                                          model: llm_model)
                end
                # Merge results
                if file_ai_result && file_ai_result['security_risks']
                  ai_analysis_result['security_risks'].concat(file_ai_result['security_risks'])
                end
              rescue StandardError => e
                puts "Error analyzing file #{file_path}: #{e.message}"
              end
            end
          end
        when :diff
          # Scan staged differences, or the branch diff when --base is given
          diff_content = get_diff
          if diff_content.empty?
            puts @options[:base] ? "No changes against #{@options[:base]} to scan." : 'No staged changes to scan.'
          elsif decision_engine?
            puts "Scanning differences (#{ai_settings.describe})..."
            units = @diff_splitter.split_by_file(diff_content)
            ai_analysis_result = checklist_scanner.scan(units, get_risks_to_check)
          else
            puts 'Scanning differences with AI...'
            current_risks_to_check = get_risks_to_check
            # @diff_splitterのインスタンス変数 @chunk_size を参照して比較
            if diff_content.length > @diff_splitter.instance_variable_get(:@chunk_size)
              puts "Diff content exceeds threshold (#{@diff_splitter.instance_variable_get(:@chunk_size)} chars), splitting..."
              ai_analysis_result = @diff_splitter.process_in_chunks(diff_content, llm_client, JSON_SCHEMA,
                                                                    @prompt_manager, current_risks_to_check, model: llm_model)
            else
              prompt = @prompt_manager.build_prompt(diff_content, current_risks_to_check, JSON_SCHEMA)
              ai_analysis_result = llm_client.analyze(prompt, JSON_SCHEMA,
                                                          model: llm_model)
            end
          end
        when :all
          # Scan entire codebase
          if decision_engine?
            puts "Scanning entire codebase (#{ai_settings.describe})..."
            files_to_scan = collect_files_from_paths(['.'], @config.ignore_patterns,
                                                     @options.fetch(:force_scan_ignored, false))
            ai_analysis_result = checklist_scanner.scan(read_units(files_to_scan), get_risks_to_check)
          elsif (full_code_content = get_full_codebase).strip.empty?
            puts 'No code found to scan.'
          else
            puts 'Scanning entire codebase with AI...'
            current_risks_to_check = get_risks_to_check
            # @diff_splitterのインスタンス変数 @chunk_size を参照して比較
            if full_code_content.length > @diff_splitter.instance_variable_get(:@chunk_size)
              puts "Full code content exceeds threshold (#{@diff_splitter.instance_variable_get(:@chunk_size)} chars), splitting..."
              ai_analysis_result = @diff_splitter.process_in_chunks(full_code_content, llm_client, JSON_SCHEMA,
                                                                    @prompt_manager, current_risks_to_check, model: llm_model)
            else
              prompt = @prompt_manager.build_prompt(full_code_content, current_risks_to_check, JSON_SCHEMA)
              ai_analysis_result = llm_client.analyze(prompt, JSON_SCHEMA,
                                                          model: llm_model)
            end
          end
        else
          puts "Unknown scan mode: #{@options[:scan_mode]}"
          puts @opt_parser
          return # Exit if scan mode is invalid
        end

        # Combine results and display report
        ai_analysis_result ||= { 'security_risks' => [] } # Ensure it's not nil
        combined_results = combine_results(ai_analysis_result, brakeman_result, bundler_audit_result)
        display_report(combined_results)

        puts 'Scan complete.'

      when :ci_setup
        generate_ci_setup(@options[:ci_service])

      when :init
        generate_initial_files

      else
        puts "Unknown command: #{@options[:command]}"
        puts @opt_parser
      end
    end

    private

    def combine_results(ai_result, brakeman_result, bundler_audit_result)
      formatted_bundler_audit_result = if bundler_audit_result && bundler_audit_result['results']
                                         { 'scan' => { 'results' => bundler_audit_result['results'] } }
                                       else
                                         { 'scan' => { 'results' => [] } }
                                       end
      {
        'ai_security_risks' => ai_result && ai_result['security_risks'] ? ai_result['security_risks'] : [],
        'static_analysis_results' => {
          'brakeman' => brakeman_result,
          'bundler_audit' => formatted_bundler_audit_result
        }
      }
    end

    def get_risks_to_check
      # 設定ファイルからチェック対象のリスクを取得し、シンボルの配列に変換する
      # 設定がない場合、LLMだけで判定するときは DEFAULT_RISKS_TO_CHECK、判定モデルを使うときは全項目を使う
      default_checks = decision_engine? ? AIAnalysisEngine::PromptManager::RISK_PROMPTS.keys : DEFAULT_RISKS_TO_CHECK
      configured_checks = @config.get('checks', default_checks)
      configured_checks.map(&:to_sym)
    end

    # Which classifier and reporter to use, from .omamorirc and the command line
    def ai_settings
      @ai_settings ||= AISettings.new(@config, ai_overrides)
    end

    def ai_overrides
      @ai_overrides ||= {}
    end

    # Stops before any scanning when the classifier or reporter settings are wrong
    def validate_ai_settings
      ai_settings
    rescue AISettings::Error => e
      puts "Configuration error: #{e.message}"
      exit 1
    end

    # The LLM that writes reports (and checks everything itself when there is no classifier)
    def llm_client
      @llm_client ||= ai_settings.build_reporter_client
    end

    def llm_model
      ai_settings.reporter_model
    end

    def decision_engine?
      ai_settings.classifier?
    end

    def checklist_scanner
      AIAnalysisEngine::ChecklistScanner.new(
        decision_client: ai_settings.build_classifier_client,
        llm_client: llm_client,
        prompt_manager: @prompt_manager,
        diff_splitter: @diff_splitter,
        json_schema: JSON_SCHEMA,
        model: llm_model,
        threshold: ai_settings.threshold,
        concurrency: ai_settings.classifier_concurrency,
        report_concurrency: ai_settings.reporter_concurrency,
        sub_checks: ai_settings.sub_checks?
      )
    end

    def read_units(file_paths)
      file_paths.filter_map do |file_path|
        relative_path = Pathname.new(file_path).relative_path_from(Pathname.pwd).to_s
        [relative_path, File.read(file_path)]
      rescue StandardError => e
        puts "Error reading file #{file_path}: #{e.message}"
        nil
      end
    end

    def parse_options
      @opt_parser = OptionParser.new do |opts|
        opts.banner = 'Usage: omamori [command] [PATH...] [options]'
        opts.separator ''
        opts.separator 'Commands:'
        opts.separator '  scan [PATH...] [options] : Scan specified files/directories or staged changes'
        opts.separator '  ci-setup [options]       : Generate CI/CD setup files'
        opts.separator '  init                     : Generate initial config file (.omamorirc) and .omamoriignore'
        opts.separator ''
        opts.separator 'Scan Options:'
        opts.on('--diff', 'Scan only the staged differences (default if no PATH is specified)') do
          @options[:scan_mode_explicit] = :diff
        end
        opts.on('--all', 'Scan the entire codebase') do
          @options[:scan_mode_explicit] = :all
        end
        opts.on('--format FORMAT', %i[console html json], 'Output format (console, html, json)') do |format|
          @options[:format] = format
        end
        opts.on('--ai', 'Run only AI analysis, skipping static analysers') do
          @options[:only_ai] = true
        end
        opts.on('--base REF', 'Scan the diff between REF and HEAD (e.g. main) instead of staged changes') do |ref|
          @options[:base] = ref
          @options[:scan_mode_explicit] ||= :diff
        end
        opts.on('--classifier PROVIDER',
                'Classifier that checks each risk as a yes/no question (typesafe, openai, ollama, or none)') do |provider|
          ai_overrides[:classifier] = provider
        end
        opts.on('--classifier-model MODEL', 'Classifier model (e.g. jev-1.13.0, gpt-6-luna)') do |model|
          ai_overrides[:classifier_model] = model
        end
        opts.on('--reporter PROVIDER',
                'LLM that writes reports: any RubyLLM provider (gemini, anthropic, openai, ...), ' \
                'or claude_code / codex to use a subscription CLI') do |provider|
          ai_overrides[:reporter] = provider
        end
        opts.on('--reporter-model MODEL', 'Reporter model (e.g. gemini-3.8-flash, claude-sonnet-5-5, sonnet)') do |model|
          ai_overrides[:reporter_model] = model
        end
        opts.on('--reporter-fallback PROVIDER',
                'Reporter asked only when the reporter refuses or fails (e.g. claude_code), or none') do |provider|
          ai_overrides[:reporter_fallback] = provider
        end
        opts.on('--reporter-fallback-model MODEL', 'Model for the fallback reporter') do |model|
          ai_overrides[:reporter_fallback_model] = model
        end
        # Older options, kept for compatibility
        opts.on('--engine ENGINE', %w[llm gemini jev openai], '(Deprecated) Use --classifier') do |engine|
          ai_overrides[:classifier] = AISettings::LEGACY_ENGINES.fetch(engine, 'none')
        end
        opts.on('--llm LLM', %w[api gemini claude codex], '(Deprecated) Use --reporter') do |llm|
          ai_overrides[:reporter] = AISettings::LEGACY_LLMS[llm] if AISettings::LEGACY_LLMS.key?(llm)
        end
        opts.on('--force-scan-ignored', 'Force scan files and directories listed in .omamoriignore') do
          @options[:force_scan_ignored] = true
        end
        opts.separator ''
        opts.separator 'CI Setup Options:'
        opts.on('--ci SERVICE', %i[github_actions gitlab_ci],
                'Generate setup for specified CI service (github_actions, gitlab_ci)') do |service|
          @options[:ci_service] = service
        end
        opts.separator ''
        opts.separator 'General Options:'
        opts.on('-h', '--help', 'Prints this help') do
          puts opts
          exit
        end
      end

      command_candidate = @args.first.to_s.downcase.tr('-', '_').to_sym
      @options[:command] = if %i[scan ci_setup init].include?(command_candidate)
                             @args.shift.tr('-', '_').to_sym
                           else
                             :scan # Default command
                           end

      begin
        @opt_parser.parse!(@args) # Parse remaining arguments for options
      rescue OptionParser::InvalidOption => e
        puts "Error: #{e.message}"
        puts @opt_parser
        exit 1
      rescue OptionParser::MissingArgument => e
        puts "Error: #{e.message}"
        puts @opt_parser
        exit 1
      end

      @target_paths = @args.dup

      # scan コマンドの場合の scan_mode の決定ロジック
      return unless @options[:command] == :scan

      if @options[:scan_mode_explicit]
        # --diff または --all が明示的に指定された場合
        @options[:scan_mode] = @options[:scan_mode_explicit]
        # パス指定があり、かつ --all や --diff もある場合、パス指定を優先する
        if !@target_paths.empty? && %i[all diff].include?(@options[:scan_mode])
          puts "Warning: Paths provided with --#{@options[:scan_mode]}. Scanning specified paths instead of full codebase/diff."
          @options[:scan_mode] = :paths
        end
      elsif !@target_paths.empty?
        # パス指定があり、--diff や --all がない場合
        @options[:scan_mode] = :paths
      else
        # パス指定がなく、--diff や --all もない場合 (例: omamori scan, omamori scan --ai)
        @options[:scan_mode] = :diff # デフォルトは diff
      end
    end

    def matches_ignore_pattern?(file_path, ignore_patterns, force_scan_ignored)
      return false if force_scan_ignored # 強制スキャンが有効な場合は無視しない

      # file_path をプロジェクトルートからの相対パスに正規化する
      # Pathname を使用して堅牢なパス操作を行う
      project_root = Pathname.pwd
      absolute_file_path = Pathname.new(file_path).expand_path
      relative_file_path = absolute_file_path.relative_path_from(project_root).to_s

      ignore_patterns.each do |pattern|
        negated = pattern.start_with?('!')
        current_pattern = negated ? pattern[1..] : pattern

        # パターンが '/' で終わる場合、ディレクトリ全体を対象とする
        if current_pattern.end_with?('/')
          # "dir/" のようなパターンは "dir/file.rb" や "dir/subdir/file.rb" にマッチする
          # relative_file_path が current_pattern (末尾の '/' を除いたもの) で始まるか確認
          if relative_file_path.start_with?(current_pattern.chomp('/')) &&
             (relative_file_path.length == current_pattern.chomp('/').length || # ディレクトリ自体にマッチ (例: "dir" vs "dir/")
              relative_file_path[current_pattern.chomp('/').length] == '/')     # ディレクトリ内のファイルにマッチ
            return !negated # マッチし、かつ否定パターンでなければ無視する
          end
        elsif File.fnmatch(current_pattern, relative_file_path, File::FNM_PATHNAME | File::FNM_DOTMATCH) || # FNM_DOTMATCH で隠しファイルも考慮
              File.fnmatch(current_pattern, File.basename(relative_file_path), File::FNM_PATHNAME | File::FNM_DOTMATCH)
          # ファイル名またはglobパターンにマッチするか確認
          # File.fnmatch はシェルのglobのように動作する
          # File::FNM_PATHNAME は '*' が '/' にマッチしないようにする
          return !negated # ファイル名のみでのマッチも考慮
        end
      end
      false # どのパターンにもマッチしなければ無視しない
    end

    def collect_files_from_paths(target_paths, ignore_patterns, force_scan_ignored)
      collected_files = []
      target_paths.each do |path|
        expanded_path = File.expand_path(path) # パスを絶対パスに展開
        if File.file?(expanded_path)
          # ファイルの場合、Rubyファイルであり、かつ無視パターンにマッチしないか確認
          if File.extname(expanded_path) == '.rb' && !matches_ignore_pattern?(expanded_path, ignore_patterns,
                                                                              force_scan_ignored)
            collected_files << expanded_path
          end
        elsif File.directory?(expanded_path)
          # ディレクトリの場合、再帰的にRubyファイルを取得し、無視パターンを適用
          Dir.glob(File.join(expanded_path, '**', '*.rb')).each do |file_path|
            abs_file_path = File.expand_path(file_path) # globで見つかったパスも絶対パスに
            unless matches_ignore_pattern?(abs_file_path, ignore_patterns, force_scan_ignored)
              collected_files << abs_file_path
            end
          end
        else
          puts "Warning: Path not found or is not a file/directory: #{path}"
        end
      end
      collected_files.uniq # 重複を除いて返す
    end

    def get_diff
      @options[:base] ? get_branch_diff(@options[:base]) : get_staged_diff
    end

    def get_staged_diff
      `git diff --staged`
    end

    # Changes on the current branch since it diverged from base (what a pull request contains)
    def get_branch_diff(base)
      `git diff #{Shellwords.escape("#{base}...HEAD")}`
    end

    def get_full_codebase
      code_content = ''
      ignore_patterns = @config.ignore_patterns
      force_scan_ignored = @options.fetch(:force_scan_ignored, false)
      # カレントディレクトリ ('.') 内のRubyファイルを収集
      files_to_scan = collect_files_from_paths(['.'], ignore_patterns, force_scan_ignored)

      files_to_scan.each do |file_path|
        # 表示用に相対パスを試みるが、エラーなら絶対パスを使用
        relative_display_path = begin
          Pathname.new(file_path).relative_path_from(Pathname.pwd).to_s
        rescue ArgumentError
          file_path # fallback to absolute path
        end
        code_content += "# File: #{relative_display_path}\n"
        code_content += File.read(file_path)
        code_content += "\n\n"
      rescue StandardError => e
        puts "Error reading file #{file_path}: #{e.message}"
      end
      code_content
    end

    def display_report(combined_results)
      case @options[:format]
      when :console
        puts @console_formatter.format(combined_results)
      when :html
        report_config = @config.get('report', {})
        output_path_prefix = report_config.fetch('output_path', './omamori_report')
        output_path = "#{output_path_prefix}.html"
        File.write(output_path, @html_formatter.format(combined_results))
        puts "HTML report generated: #{output_path}"
      when :json
        report_config = @config.get('report', {})
        output_path_prefix = report_config.fetch('output_path', './omamori_report')
        output_path = "#{output_path_prefix}.json"
        File.write(output_path, @json_formatter.format(combined_results))
        puts "JSON report generated: #{output_path}"
      end
    end

    def generate_ci_setup(ci_service)
      case ci_service
      when :github_actions
        generate_github_actions_workflow
      when :gitlab_ci
        generate_gitlab_ci_workflow
      else
        puts "Unsupported CI service: #{ci_service}. Supported: github_actions, gitlab_ci"
        puts @opt_parser # ヘルプメッセージを表示
      end
    end

    def generate_github_actions_workflow
      workflow_content = <<~YAML
        # .github/workflows/omamori_scan.yml
        name: Omamori Security Scan

        on: [push, pull_request]

        jobs:
          security_scan:
            runs-on: ubuntu-latest

            steps:
            - name: Checkout code
              uses: actions/checkout@v4 # Recommended to use specific version
              with:
                fetch-depth: 0 # Needed to diff against the base branch

            - name: Set up Ruby
              uses: ruby/setup-ruby@v1 # Recommended to use specific version
              with:
                ruby-version: '3.0' # Specify your project's Ruby version

            - name: Install dependencies
              run: bundle install

            # Optional: Cache gems to speed up future builds
            # - name: Cache gems
            #   uses: actions/cache@v3
            #   with:
            #     path: vendor/bundle
            #     key: ${{ runner.os }}-gems-${{ hashFiles('**/Gemfile.lock') }}
            #     restore-keys: |
            #       ${{ runner.os }}-gems-

            - name: Install Brakeman (if not in Gemfile)
              run: gem install brakeman --no-document || true

            - name: Install Bundler-Audit (if not in Gemfile)
              run: gem install bundler-audit --no-document || true

            - name: Run Omamori Scan
              env:
                GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }} # Ensure GEMINI_API_KEY is set in GitHub Secrets
                # TYPESAFE_API_KEY: ${{ secrets.TYPESAFE_API_KEY }} # For classifier: typesafe
                # OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }} # For classifier: openai, or an OpenAI reporter
              # Example: Scan all files on push to main, diff on PRs
              # This logic might need adjustment based on your workflow preference
              run: |
                if [ "$GITHUB_EVENT_NAME" == "pull_request" ]; then
                  bundle exec omamori scan --base "origin/$GITHUB_BASE_REF" --format console
                else
                  bundle exec omamori scan --all --format console
                fi
      YAML
      ci_config = @config.get('ci_setup', {})
      output_path = ci_config.fetch('github_actions_path', '.github/workflows/omamori_scan.yml')
      FileUtils.mkdir_p(File.dirname(output_path)) # Ensure directory exists
      File.write(output_path, workflow_content)
      puts "GitHub Actions workflow generated: #{output_path}"
    end

    def generate_gitlab_ci_workflow
      workflow_content = <<~YAML
        # .gitlab-ci.yml
        stages:
          - security_scan

        omamori_security_scan:
          stage: security_scan
          image: ruby:3.0 # Specify your project's Ruby version
          # Cache gems
          cache:
            key:
              files:
                - Gemfile.lock
            paths:
              - vendor/bundle
          before_script:
            - apt-get update -qq && apt-get install -y --no-install-recommends nodejs # If needed for JS runtime
            - gem install bundler --no-document
            - bundle install --jobs $(nproc) --retry 3 --path vendor/bundle
            - gem install brakeman --no-document || true
            - gem install bundler-audit --no-document || true
          script:
            # Example: Scan all files on pipelines for the default branch, diff on merge requests
            - |
              if [ "$CI_PIPELINE_SOURCE" == "merge_request_event" ]; then
                bundle exec omamori scan --base "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --format console
              else
                bundle exec omamori scan --all --format console
              fi
          variables:
            GEMINI_API_KEY: $GEMINI_API_KEY # Set GEMINI_API_KEY as a CI/CD variable in GitLab
            # TYPESAFE_API_KEY: $TYPESAFE_API_KEY # For classifier: typesafe
            # OPENAI_API_KEY: $OPENAI_API_KEY # For classifier: openai, or an OpenAI reporter
            GIT_DEPTH: "0" # Needed to diff against the target branch
          rules:
            - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
      YAML
      ci_config = @config.get('ci_setup', {})
      output_path = ci_config.fetch('gitlab_ci_path', '.gitlab-ci.yml')
      File.write(output_path, workflow_content)
      puts "GitLab CI workflow generated: #{output_path}"
    end

    DEFAULT_OMAMORIIGNORE_CONTENT = <<~IGNORE
      # Omamori ignore file
      # Add files and directories to ignore during Omamori scans.
      # Lines starting with # are comments.
      # Globs are supported (e.g., *.tmp, spec/fixtures/)
      # Negation with ! (e.g., !important.log) - not fully implemented in current basic matcher

      # Log files
      log/
      *.log

      # Temporary files
      tmp/
      *.tmp
      *.swp
      *.swo

      # OS-specific files
      .DS_Store
      Thumbs.db

      # Vendor directory (often contains third-party code)
      vendor/bundle/

      # Coverage reports
      coverage/

      # Node.js dependencies
      node_modules/

      # Build artifacts
      pkg/

      # Test files and fixtures (optional, consider if they contain sensitive examples)
      # spec/
      # test/
      # features/

      # Database schema and migrations (usually not directly exploitable via code injection)
      # db/schema.rb
      # db/migrate/

      # Assets (compiled or static, less likely to have Ruby vulnerabilities)
      # app/assets/builds/
      # public/assets/
    IGNORE

    def generate_initial_files
      config_content = <<~YAML
        # .omamorirc
        # Configuration file for omamori gem

        # API keys are read from environment variables: GEMINI_API_KEY (default reporter),
        # TYPESAFE_API_KEY (classifier: typesafe), OPENAI_API_KEY, ANTHROPIC_API_KEY, ... for other providers.

        # Classifier (optional): a fast decision model that checks each risk as a yes/no question.
        # Only the flagged checks are sent to the reporter. Without it, the reporter checks everything.
        # classifier:
        #   provider: "typesafe"   # typesafe / openai / ollama
        #   model: "jev-1.13.0"
        #   threshold: 0.3

        # Reporter (optional, default: gemini / gemini-3.8-flash): the LLM that writes reports.
        # Any RubyLLM provider, or claude_code / codex to use a subscription CLI (claude -p / codex exec).
        # reporter:
        #   provider: "anthropic"
        #   model: "claude-sonnet-5-5"

        # Security checks to enable (optional, default: all implemented checks).
        # Provide a list of symbols. Example:
        # checks:
        #   - xss
        #   - csrf
        #   - idor
        #   - open_redirect
        #   # Add other risk symbols from Omamori::AIAnalysisEngine::PromptManager::RISK_PROMPTS.keys

        # Custom prompt templates (optional).
        # prompt_templates:
        #   default: |
        #     Analyze the following Ruby code for security vulnerabilities.
        #     Focus on: %<risk_list>s.
        #     Report in JSON format: %<json_schema>s.
        #     Code:
        #     %<code_content>s

        # Report output settings (optional).
        # report:
        #   output_path: "./omamori_scan_results" # Prefix for html/json reports
        #   html_template: "custom_report_template.erb" # Path to custom ERB template

        # Static analyser options (optional).
        # Provide options as a hash.
        # static_analysers:
        #   brakeman:
        #     options: {"--skip-checks": "BasicAuth", "--no-progress": true}
        #   bundler_audit:
        #     options: {quiet: true}

        # Language for AI analysis details (optional, default: "en").
        # Supported languages depend on the AI model.
        # language: "ja"

        # Chunk size for splitting large code content for AI analysis (optional, default: 8000 characters).
        # chunk_size: 10000

        # CI setup file paths (optional).
        # ci_setup:
        #   github_actions_path: ".github/workflows/custom_omamori_scan.yml"
        #   gitlab_ci_path: ".custom-gitlab-ci.yml"
      YAML
      config_output_path = Omamori::Config::DEFAULT_CONFIG_PATH
      if File.exist?(config_output_path)
        puts "Config file already exists at #{config_output_path}. Aborting .omamorirc generation."
      else
        File.write(config_output_path, config_content)
        puts "Config file generated: #{config_output_path}"
        puts 'Set GEMINI_API_KEY (or the key for the provider you choose) in your environment before scanning.'
      end

      ignore_output_path = Omamori::Config::DEFAULT_IGNORE_PATH
      if File.exist?(ignore_output_path)
        puts ".omamoriignore file already exists at #{ignore_output_path}. Aborting .omamoriignore generation."
      else
        File.write(ignore_output_path, DEFAULT_OMAMORIIGNORE_CONTENT)
        puts ".omamoriignore file generated: #{ignore_output_path}"
      end
    end
  end
end
