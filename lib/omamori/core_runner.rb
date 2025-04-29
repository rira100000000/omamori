# frozen_string_literal: true

require 'optparse'
require_relative 'ai_analysis_engine/gemini_client'
require_relative 'ai_analysis_engine/prompt_manager' # Require PromptManager
require_relative 'ai_analysis_engine/diff_splitter' # Require DiffSplitter
require_relative 'report_generator/console_formatter' # Require ConsoleFormatter
require_relative 'report_generator/html_formatter' # Require HTMLFormatter
require_relative 'report_generator/json_formatter' # Require JSONFormatter
require_relative 'static_analysers/brakeman_runner' # Require BrakemanRunner
require_relative 'static_analysers/bundler_audit_runner' # Require BundlerAuditRunner
require 'json' # Required for JSON Schema
require_relative 'config' # Require Config class

module Omamori
  class CoreRunner
    # Define the JSON Schema for Structured Output
    JSON_SCHEMA = {
      "type": "object",
      "properties": {
        "security_risks": {
          "type": "array",
          "description": "検出されたセキュリティリスクのリスト。",
          "items": {
            "type": "object",
            "properties": {
              "type": {
                "type": "string",
                "description": "検出されたリスクの種類 (例: XSS, CSRF, IDORなど)。3.3の診断対象脆弱性リストのいずれかであること。"
              },
              "location": {
                "type": "string",
                "description": "リスクが存在するコードのファイル名、行番号、またはコードスニペット。差分分析の場合は差分の該当箇所を示す形式 (例: ファイル名:+行番号) であること。"
              },
              "details": {
                "type": "string",
                "description": "リスクの詳細な説明と、なぜそれがリスクなのかの理由。"
              },
              "severity": {
                "type": "string",
                "description": "リスクの深刻度。",
                "enum": ["Critical", "High", "Medium", "Low", "Info"]
              },
              "code_snippet": {
                "type": "string",
                "description": "該当するコードスニペット。"
              }
            },
            "required": ["type", "location", "details", "severity"]
          }
        }
      },
      "required": ["security_risks"]
    }.freeze # Freeze the hash to make it immutable

    # TODO: Get risks to check from config file
    RISKS_TO_CHECK = [
      :xss, :csrf, :idor, :open_redirect, :ssrf, :session_fixation
      # TODO: Add other risks from requirements
    ].freeze

    # TODO: Determine threshold for splitting based on token limits
    SPLIT_THRESHOLD = 7000 # Characters as a proxy for tokens

    def initialize(args)
      @args = args
      @options = { command: :scan, format: :console } # Default command is scan, default format is console
      @config = Omamori::Config.new # Initialize Config

      # Initialize components with config
      api_key = @config.get("api_key", ENV["GEMINI_API_KEY"]) # Get API key from config or environment variable
      gemini_model = @config.get("model", "gemini-1.5-pro-latest") # Get Gemini model from config
      @gemini_client = AIAnalysisEngine::GeminiClient.new(api_key)
      @prompt_manager = AIAnalysisEngine::PromptManager.new(@config) # Pass the entire config object
      # Get chunk size from config, default to 7000 characters if not specified
      chunk_size = @config.get("chunk_size", SPLIT_THRESHOLD)
      @diff_splitter = AIAnalysisEngine::DiffSplitter.new(chunk_size: chunk_size) # Pass chunk size to DiffSplitter
      # Get report output path and html template path from config
      report_config = @config.get("report", {})
      report_output_path = report_config.fetch("output_path", "./omamori_report")
      html_template_path = report_config.fetch("html_template", nil) # Default to nil, formatter will use default template
      @console_formatter = ReportGenerator::ConsoleFormatter.new # TODO: Pass config for colors/options
      @html_formatter = ReportGenerator::HTMLFormatter.new(report_output_path, html_template_path) # Pass output path and template path
      @json_formatter = ReportGenerator::JSONFormatter.new(report_output_path) # Pass output path
      # Get static analyser options from config
      static_analyser_config = @config.get("static_analysers", {})
      brakeman_options = static_analyser_config.fetch("brakeman", {}).fetch("options", {}) # Default to empty hash
      bundler_audit_options = static_analyser_config.fetch("bundler_audit", {}).fetch("options", {}) # Default to empty hash
      @brakeman_runner = StaticAnalysers::BrakemanRunner.new(brakeman_options) # Pass options
      @bundler_audit_runner = StaticAnalysers::BundlerAuditRunner.new(bundler_audit_options) # Pass options
    end

    def run
      parse_options

      case @options[:command]
      when :scan
        # Run static analysers first unless --ai option is specified
        brakeman_result = nil
        bundler_audit_result = nil
        unless @options[:only_ai]
          brakeman_result = @brakeman_runner.run
          bundler_audit_result = @bundler_audit_runner.run
        end

        # Perform AI analysis
        analysis_result = nil
        case @options[:scan_mode]
        when :diff
          diff_content = get_staged_diff
          if diff_content.empty?
            puts "No staged changes to scan."
            return
          end
          puts "Scanning staged differences with AI..."
          if diff_content.length > SPLIT_THRESHOLD # TODO: Use token count
            puts "Diff content exceeds threshold, splitting..."
            analysis_result = @diff_splitter.process_in_chunks(diff_content, @gemini_client, JSON_SCHEMA, @prompt_manager, get_risks_to_check, model: @config.get("model", "gemini-1.5-pro-latest"))
          else
            prompt = @prompt_manager.build_prompt(diff_content, get_risks_to_check, JSON_SCHEMA)
            analysis_result = @gemini_client.analyze(prompt, JSON_SCHEMA, model: @config.get("model", "gemini-1.5-pro-latest"))
          end
        when :all
          full_code_content = get_full_codebase
          if full_code_content.strip.empty?
            puts "No code found to scan."
            return
          end
          puts "Scanning entire codebase with AI..."
          if full_code_content.length > SPLIT_THRESHOLD # TODO: Use token count
            puts "Full code content exceeds threshold, splitting..."
            analysis_result = @diff_splitter.process_in_chunks(full_code_content, @gemini_client, JSON_SCHEMA, @prompt_manager, get_risks_to_check, model: @config.get("model", "gemini-1.5-pro-latest"))
          else
            prompt = @prompt_manager.build_prompt(full_code_content, get_risks_to_check, JSON_SCHEMA)
            analysis_result = @gemini_client.analyze(prompt, JSON_SCHEMA, model: @config.get("model", "gemini-1.5-pro-latest"))
          end
        end

        # Combine results and display report
        combined_results = combine_results(analysis_result, brakeman_result, bundler_audit_result)
        display_report(combined_results)

        puts "Scan complete."

      when :ci_setup
        generate_ci_setup(@options[:ci_service])

      when :init
        generate_config_file # Generate initial config file

      else
        puts "Unknown command: #{@options[:command]}"
        puts @opt_parser # Display help for unknown command
      end
    end

    private

    # Combine AI analysis results and static analyser results
    def combine_results(ai_result, brakeman_result, bundler_audit_result)
      # Transform bundler_audit_result to match the expected structure in tests/formatters
      formatted_bundler_audit_result = if bundler_audit_result && bundler_audit_result["results"]
                                         { "scan" => { "results" => bundler_audit_result["results"] } }
                                       else
                                         # Return a structure that formatters can handle gracefully
                                         { "scan" => { "results" => [] } } # Or nil, depending on desired behavior when no results
                                       end

      combined = {
        "ai_security_risks" => ai_result && ai_result["security_risks"] ? ai_result["security_risks"] : [],
        "static_analysis_results" => {
          "brakeman" => brakeman_result,
          "bundler_audit" => formatted_bundler_audit_result # Use the transformed result
        }
      }
      combined
    end

    # Default risks to check if not specified in config
    DEFAULT_RISKS_TO_CHECK = [
      :xss, :csrf, :idor, :open_redirect, :ssrf, :session_fixation
      # TODO: Add other risks from requirements
    ].freeze

    def get_risks_to_check
      # Get risks to check from config, default to hardcoded list if not specified
      @config.get("checks", DEFAULT_RISKS_TO_CHECK)
    end

    def parse_options
      @opt_parser = OptionParser.new do |opts|
        opts.banner = "Usage: omamori [command] [options]"

        opts.separator ""
        opts.separator "Commands:"
        opts.separator "  scan [options]  : Scan code or diff for security vulnerabilities"
        opts.separator "  ci-setup [options] : Generate CI/CD setup files"
        opts.separator "  init          : Generate initial config file (.omamorirc)"

        opts.separator ""
        opts.separator "Scan Options:"
        opts.on("--diff", "Scan only the staged differences (default)") do
          @options[:scan_mode] = :diff
        end

        opts.on("--all", "Scan the entire codebase") do
          @options[:scan_mode] = :all
        end

        opts.on("--format FORMAT", [:console, :html, :json], "Output format (console, html, json)") do |format|
          @options[:format] = format
        end

        opts.on("--ai", "Run only AI analysis, skipping static analysers") do
          @options[:only_ai] = true
        end

        opts.separator ""
        opts.separator "CI Setup Options:"
        opts.on("--ci SERVICE", [:github_actions, :gitlab_ci], "Generate setup for specified CI service (github_actions, gitlab_ci)") do |service|
          @options[:ci_service] = service
        end

        opts.separator ""
        opts.separator "General Options:"
        opts.on("-h", "--help", "Prints this help") do
          puts opts
          exit
        end
      end

      # Determine command before parsing options
      # Use @args instead of ARGV
      command = @args.first.to_s.downcase.to_sym rescue nil
      if [:scan, :ci_setup, :init].include?(command)
        @options[:command] = @args.shift.to_sym # Consume the command argument from @args
      else
        @options[:command] = :scan # Default command is scan if not specified
      end

      @opt_parser.parse!(@args)

      # Default scan mode to diff if command is scan and mode is not specified
      @options[:scan_mode] ||= :diff if @options[:command] == :scan

      # Display help if command is not recognized after parsing
      unless [:scan, :ci_setup, :init].include?(@options[:command])
        puts @opt_parser
        exit
      end
    end

    def get_staged_diff
      `git diff --staged`
    end

    def get_full_codebase
      code_content = ""
      # TODO: Get target directories/files from config
      Dir.glob("**/*.rb").each do |file_path|
        next if file_path.include?("vendor/") || file_path.include?(".git/") || file_path.include?(".cline/") # Exclude vendor, .git, and .cline directories

        begin
          code_content += "# File: #{file_path}\n"
          code_content += File.read(file_path)
          code_content += "\n\n"
        rescue => e
          puts "Error reading file #{file_path}: #{e.message}"
        end
      end
      code_content
    end

    def display_report(combined_results)
      case @options[:format]
      when :console
        puts @console_formatter.format(combined_results)
      when :html
        # Get output file path from config/options
        report_config = @config.get("report", {})
        output_path_prefix = report_config.fetch("output_path", "./omamori_report")
        output_path = "#{output_path_prefix}.html"
        File.write(output_path, @html_formatter.format(combined_results))
        puts "HTML report generated: #{output_path}"
      when :json
        # Get output file path from config/options
        report_config = @config.get("report", {})
        output_path_prefix = report_config.fetch("output_path", "./omamori_report")
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
        puts "Unsupported CI service: #{ci_service}"
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
              uses: actions/checkout@v4

            - name: Set up Ruby
              uses: ruby/setup-ruby@v1
              with:
                ruby-version: 2.7 # Or your project's Ruby version

            - name: Install dependencies
              run: bundle install

            - name: Install Brakeman (if not in Gemfile)
              run: gem install brakeman || true # Install if not already present

            - name: Install Bundler-Audit (if not in Gemfile)
              run: gem install bundler-audit || true # Install if not already present

            - name: Run Omamori Scan
              env:
                GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }} # Ensure you add GEMINI_API_KEY to GitHub Secrets
              run: bundle exec omamori scan --all --format console # Or --diff for diff scan

      YAML
      # Get output file path from config/options, default to .github/workflows/omamori_scan.yml
      ci_config = @config.get("ci_setup", {})
      output_path = ci_config.fetch("github_actions_path", ".github/workflows/omamori_scan.yml")
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
          image: ruby:latest # Use a Ruby image
          before_script:
            - apt-get update -qq && apt-get install -y nodejs # Install nodejs if needed for some tools
            - gem install bundler # Ensure bundler is installed
            - bundle install --jobs $(nproc) --retry 3 # Install dependencies
            - gem install brakeman || true # Install Brakeman if not in Gemfile
            - gem install bundler-audit || true # Install Bundler-Audit if not in Gemfile
          script:
            - bundle exec omamori scan --all --format console # Or --diff for diff scan
          variables:
            GEMINI_API_KEY: $GEMINI_API_KEY # Ensure you set GEMINI_API_KEY as a CI/CD variable in GitLab
          # Optional: Define rules for when to run this job
          # rules:
          #   - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
          #   - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'

      YAML
      # Get output file path from config/options, default to .gitlab-ci.yml
      ci_config = @config.get("ci_setup", {})
      output_path = ci_config.fetch("gitlab_ci_path", ".gitlab-ci.yml")
      File.write(output_path, workflow_content)
      puts "GitLab CI workflow generated: #{output_path}"
    end

    def generate_config_file
      config_content = <<~YAML
        # .omamorirc
        # Configuration file for omamori gem

        # Gemini API Key (required for AI analysis)
        # You can also set this via the GEMINI_API_KEY environment variable
        api_key: YOUR_GEMINI_API_KEY # Replace with your actual API key

        # Gemini Model to use (optional, default: gemini-1.5-pro-latest)
        # model: gemini-1.5-flash-latest

        # Security checks to enable (optional, default: all implemented checks)
        # checks:
        #   xss: true
        #   csrf: true
        #   idor: true
        #   ...

        # Custom prompt templates (optional)
        # prompt_templates:
        #   default: |
        #     Your custom prompt template here...

        # Report output settings (optional)
        # report:
        #   output_path: ./omamori_report # Output directory/prefix for html/json reports
        #   html_template: path/to/custom/template.erb # Custom HTML template

        # Static analyser options (optional)
        # static_analysers:
        #   brakeman:
        #     options: "--force" # Additional Brakeman options
        #   bundler_audit:
        #     options: "--quiet" # Additional Bundler-Audit options
        
                # Language setting for AI analysis details (optional, default: en)
                # language: ja
        
              YAML
      # TODO: Specify output file path from options
      output_path = Omamori::Config::DEFAULT_CONFIG_PATH
      if File.exist?(output_path)
        puts "Config file already exists at #{output_path}. Aborting init."
      else
        File.write(output_path, config_content)
        puts "Config file generated: #{output_path}"
        puts "Please replace 'YOUR_GEMINI_API_KEY' with your actual API key."
      end
    end
  end
end