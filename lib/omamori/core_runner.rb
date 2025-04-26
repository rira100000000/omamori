# frozen_string_literal: true

require 'optparse'
require 'optparse'
require_relative 'ai_analysis_engine/gemini_client'
require_relative 'ai_analysis_engine/prompt_manager' # Require PromptManager
require_relative 'ai_analysis_engine/diff_splitter' # Require DiffSplitter
require_relative 'report_generator/console_formatter' # Require ConsoleFormatter
require_relative 'report_generator/html_formatter' # Require HTMLFormatter
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
    end

    def run
      parse_options

      case @options[:scan_mode]
      when :diff
        diff_content = get_staged_diff
        if diff_content.empty?
          puts "No staged changes to scan."
          return
        end
        puts "Scanning staged differences..."
        if diff_content.length > SPLIT_THRESHOLD
          puts "Diff content exceeds threshold, splitting..."
          analysis_result = @diff_splitter.process_in_chunks(diff_content, @gemini_client, JSON_SCHEMA, @prompt_manager, RISKS_TO_CHECK)
        else
          prompt = @prompt_manager.build_prompt(diff_content, RISKS_TO_CHECK)
          analysis_result = @gemini_client.analyze(prompt, JSON_SCHEMA)
        end
        display_report(analysis_result) # Display report
      when :all
        full_code_content = get_full_codebase
        if full_code_content.strip.empty?
          puts "No code found to scan."
          return
        end
        puts "Scanning entire codebase..."
        if full_code_content.length > SPLIT_THRESHOLD
          puts "Full code content exceeds threshold, splitting..."
          analysis_result = @diff_splitter.process_in_chunks(full_code_content, @gemini_client, JSON_SCHEMA, @prompt_manager, RISKS_TO_CHECK)
        else
          prompt = @prompt_manager.build_prompt(full_code_content, RISKS_TO_CHECK)
          analysis_result = @gemini_client.analyze(prompt, JSON_SCHEMA)
        end
        display_report(analysis_result) # Display report
      end

      puts "Scan complete."
    end

    private

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

    def display_report(analysis_result)
      case @options[:format]
      when :console
        puts @console_formatter.format(analysis_result)
      when :html
        # TODO: Specify output file path from config/options
        output_path = "omamori_report.html"
        File.write(output_path, @html_formatter.format(analysis_result))
        puts "HTML report generated: #{output_path}"
      when :json
        # TODO: Implement JSON formatter and output to file
        puts "JSON output not yet implemented."
      end
    end
  end
end