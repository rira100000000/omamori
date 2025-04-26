# frozen_string_literal: true

require 'optparse'
require_relative 'ai_analysis_engine/gemini_client'
require_relative 'ai_analysis_engine/prompt_manager' # Require PromptManager
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

    def initialize(args)
      @args = args
      @options = {}
      # TODO: Get API key from config file
      @gemini_client = AIAnalysisEngine::GeminiClient.new("YOUR_DUMMY_API_KEY") # Use dummy key for now
      @prompt_manager = AIAnalysisEngine::PromptManager.new # Initialize PromptManager
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
        # Use PromptManager to build the prompt for diff scan
        prompt = @prompt_manager.build_prompt(diff_content, RISKS_TO_CHECK)
        analysis_result = @gemini_client.analyze(prompt, JSON_SCHEMA)
        puts "Analysis Result: #{analysis_result}" # TODO: Pass result to ReportGenerator
      when :all
        full_code_content = get_full_codebase
        if full_code_content.strip.empty?
          puts "No code found to scan."
          return
        end
        puts "Scanning entire codebase..."
        # Use PromptManager to build the prompt for full code scan
        prompt = @prompt_manager.build_prompt(full_code_content, RISKS_TO_CHECK)
        analysis_result = @gemini_client.analyze(prompt, JSON_SCHEMA)
        puts "Analysis Result: #{analysis_result}" # TODO: Pass result to ReportGenerator
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
  end
end