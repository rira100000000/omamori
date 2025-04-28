# frozen_string_literal: true

require 'json' # Bundler-Audit can output JSON

module Omamori
  module StaticAnalysers
    class BundlerAuditRunner
      def initialize(options = {})
        @options = options
      end

      def run
        # TODO: Determine Bundler-Audit command based on options
        # Example: bundle audit --format json
        # Include options passed during initialization
        # Build options string from the options hash
        options_string = @options.map { |key, value| value == true ? key.to_s : "#{key} #{value}" }.join(" ")
        bundler_audit_command = "bundle audit --format json#{options_string.empty? ? '' : " #{options_string}"}"

        begin
          # Execute the Bundler-Audit command and capture output
          # Note: bundle audit exits with non-zero status if vulnerabilities are found
          # We need to capture stdout and stderr regardless of exit status
          bundler_audit_output = `#{bundler_audit_command} 2>&1`

          # Parse the JSON output
          # Bundler-Audit JSON output structure might vary, need to confirm
          # Assuming it returns a JSON object with vulnerability information
          parsed_output = JSON.parse(bundler_audit_output)
          # Validate the parsed output structure
          if parsed_output.is_a?(Hash) && parsed_output.key?('results')
            # Return the entire parsed output hash
            parsed_output
          else
            puts "Error: Unexpected Bundler-Audit JSON output structure."
            puts "Raw output:\n#{bundler_audit_output}"
            nil # Return nil if the structure is unexpected
          end
        rescue Errno::ENOENT
          puts "Error: bundle command not found. Is Bundler installed?"
          nil
        rescue JSON::ParserError
          puts "Error: Failed to parse Bundler-Audit JSON output."
          puts "Raw output:\n#{bundler_audit_output}"
          nil
        rescue => e
          puts "An error occurred during Bundler-Audit execution: #{e.message}"
          nil
        end
      end
    end
  end
end