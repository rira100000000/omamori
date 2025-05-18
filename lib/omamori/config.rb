# frozen_string_literal: true

require 'yaml'

module Omamori
  class Config
    DEFAULT_CONFIG_PATH = ".omamorirc"
    DEFAULT_IGNORE_PATH = ".omamoriignore"

    attr_reader :ignore_patterns

    def initialize(config_path = DEFAULT_CONFIG_PATH)
      @config_path = config_path
      @config = load_config
      @ignore_patterns = load_ignore_patterns # Load ignore patterns
      validate_config # Add validation after loading
    end

    def get(key, default = nil)
      @config.fetch(key.to_s, default)
    end

    # Add validation methods
    private

    def validate_config
      validate_api_key
      validate_model
      validate_checks
      validate_prompt_templates
      validate_report_settings
      validate_static_analyser_settings
      validate_ci_setup_settings # Add CI setup validation
      validate_language # Add language validation
    end

    def validate_api_key
      api_key = @config["api_key"]
      if api_key && !api_key.is_a?(String)
        puts "Warning: Config 'api_key' should be a string."
      end
    end

    def validate_model
      model = @config["model"]
      if model && !model.is_a?(String)
        puts "Warning: Config 'model' should be a string."
      end
    end

    def validate_checks
      checks = @config["checks"]
      if checks && !checks.is_a?(Array)
        puts "Warning: Config 'checks' should be an array."
      end
    end

    def validate_prompt_templates
      prompt_templates = @config["prompt_templates"]
      if prompt_templates && !prompt_templates.is_a?(Hash)
        puts "Warning: Config 'prompt_templates' should be a hash."
      end
    end

    def validate_report_settings
      report = @config["report"]
      if report
        unless report.is_a?(Hash)
          puts "Warning: Config 'report' should be a hash."
          return
        end
        if report.key?("output_path") && !report["output_path"].is_a?(String)
          puts "Warning: Config 'report.output_path' should be a string."
        end
        if report.key?("html_template") && !report["html_template"].is_a?(String)
          puts "Warning: Config 'report.html_template' should be a string."
        end
      end
    end

    def validate_static_analyser_settings
      static_analysers = @config["static_analysers"]
      if static_analysers
        unless static_analysers.is_a?(Hash)
          puts "Warning: Config 'static_analysers' should be a hash."
          return
        end
        if static_analysers.key?("brakeman")
          brakeman_config = static_analysers["brakeman"]
          unless brakeman_config.is_a?(Hash)
            puts "Warning: Config 'static_analysers.brakeman' should be a hash."
          else
            if brakeman_config.key?("options") && !brakeman_config["options"].is_a?(String)
              puts "Warning: Config 'static_analysers.brakeman.options' should be a string."
            end
          end
        end
        if static_analysers.key?("bundler_audit")
          bundler_audit_config = static_analysers["bundler_audit"]
          unless bundler_audit_config.is_a?(Hash)
            puts "Warning: Config 'static_analysers.bundler_audit' should be a hash."
          else
            if bundler_audit_config.key?("options") && !bundler_audit_config["options"].is_a?(String)
              puts "Warning: Config 'static_analysers.bundler_audit.options' should be a string."
            end
          end
        end
      end
    end


    def validate_ci_setup_settings
      ci_setup = @config["ci_setup"]
      if ci_setup
        unless ci_setup.is_a?(Hash)
          puts "Warning: Config 'ci_setup' should be a hash."
          return
        end
        if ci_setup.key?("github_actions_path") && !ci_setup["github_actions_path"].is_a?(String)
          puts "Warning: Config 'ci_setup.github_actions_path' should be a string."
        end
        if ci_setup.key?("gitlab_ci_path") && !ci_setup["gitlab_ci_path"].is_a?(String)
          puts "Warning: Config 'ci_setup.gitlab_ci_path' should be a string."
        end
      end
    end

    def validate_language
      language = @config["language"]
      if language && !language.is_a?(String)
        puts "Warning: Config 'language' should be a string."
      end
    end

    # Load .omamoriignore file and return an array of ignore patterns
    def load_ignore_patterns
      ignore_path = DEFAULT_IGNORE_PATH
      if File.exist?(ignore_path)
        begin
          File.readlines(ignore_path, chomp: true).reject do |line|
            line.strip.empty? || line.strip.start_with?('#')
          end
        rescue => e
          puts "Warning: Error reading .omamoriignore file #{ignore_path}: #{e.message}"
          [] # Return empty array if reading fails
        end
      else
        [] # Return empty array if file does not exist
      end
    end

    def load_config
      if File.exist?(@config_path)
        begin
          YAML.load_file(@config_path) || {}
        rescue Psych::SyntaxError => e
          puts "Error parsing config file #{@config_path}: #{e.message}"
          {}
        end
      else
        {} # Return empty hash if config file does not exist
      end
    end
  end
end