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
      @options = { format: :console } # Default format is console
      # TODO: Get API key from config file
      @gemini_client = AIAnalysisEngine::GeminiClient.new("YOUR_DUMMY_API_KEY") # Use dummy key for now
      @prompt_manager = AIAnalysisEngine::PromptManager.new # Initialize PromptManager
      @diff_splitter = AIAnalysisEngine::DiffSplitter.new # Initialize DiffSplitter
      @console_formatter = ReportGenerator::ConsoleFormatter.new # Initialize ConsoleFormatter
      @html_formatter = ReportGenerator::HTMLFormatter.new # Initialize HTMLFormatter
      @json_formatter = ReportGenerator::JSONFormatter.new # Initialize JSONFormatter
      @brakeman_runner = StaticAnalysers::BrakemanRunner.new # Initialize BrakemanRunner
      @bundler_audit_runner = StaticAnalysers::BundlerAuditRunner.new # Initialize BundlerAuditRunner
    end

    def run
      parse_options

      # Run static analysers first
      brakeman_result = @brakeman_runner.run
      bundler_audit_result = @bundler_audit_runner.run

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
        if diff_content.length > SPLIT_THRESHOLD
          puts "Diff content exceeds threshold, splitting..."
          analysis_result = @diff_splitter.process_in_chunks(diff_content, @gemini_client, JSON_SCHEMA, @prompt_manager, RISKS_TO_CHECK)
        else
          prompt = @prompt_manager.build_prompt(diff_content, RISKS_TO_CHECK)
          analysis_result = @gemini_client.analyze(prompt, JSON_SCHEMA)
        end
      when :all
        full_code_content = get_full_codebase
        if full_code_content.strip.empty?
          puts "No code found to scan."
          return
        end
        puts "Scanning entire codebase with AI..."
        if full_code_content.length > SPLIT_THRESHOLD
          puts "Full code content exceeds threshold, splitting..."
          analysis_result = @diff_splitter.process_in_chunks(full_code_content, @gemini_client, JSON_SCHEMA, @prompt_manager, RISKS_TO_CHECK)
        else
          prompt = @prompt_manager.build_prompt(full_code_content, RISKS_TO_CHECK)
          analysis_result = @gemini_client.analyze(prompt, JSON_SCHEMA)
        end
      end

      # Combine results and display report
      combined_results = combine_results(analysis_result, brakeman_result, bundler_audit_result)
      display_report(combined_results)

      puts "Scan complete."
    end

    private

    # Combine AI analysis results and static analyser results
    def combine_results(ai_result, brakeman_result, bundler_audit_result)
      combined = {
        "ai_security_risks" => ai_result && ai_result["security_risks"] ? ai_result["security_risks"] : [],
        "static_analysis_results" => {
          "brakeman" => brakeman_result,
          "bundler_audit" => bundler_audit_result
        }
      }
      combined
    end

    def parse_options
      OptionParser.new do |opts|
        opts.banner = "Usage: omamori scan [options]"

        opts.on("--diff", "Scan only the staged differences (default)") do
          @options[:scan_mode] = :diff
        end

        opts.on("--all", "Scan the entire codebase") do
          @options[:scan_mode] = :all
        end

        opts.on("--format FORMAT", [:console, :html, :json], "Output format (console, html, json)") do |format|
          @options[:format] = format
        end

        opts.on("-h", "--help", "Prints this help") do
          puts opts
          exit
        end
      end.parse!(@args)

      @options[:scan_mode] ||= :diff # Default to diff scan
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
        # TODO: Specify output file path from config/options
        output_path = "omamori_report.html"
        File.write(output_path, @html_formatter.format(combined_results))
        puts "HTML report generated: #{output_path}"
      when :json
        # TODO: Specify output file path from config/options
        output_path = "omamori_report.json"
        File.write(output_path, @json_formatter.format(combined_results))
        puts "JSON report generated: #{output_path}"
      end
    end
  end
end