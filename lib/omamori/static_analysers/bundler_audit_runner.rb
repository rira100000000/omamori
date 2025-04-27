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
        bundler_audit_command = "bundle audit --format json#{@options.empty? ? '' : " #{@options}"}"

        begin
          # Execute the Bundler-Audit command and capture output
          # Note: bundle audit exits with non-zero status if vulnerabilities are found
          # We need to capture stdout and stderr regardless of exit status
          bundler_audit_output = `#{bundler_audit_command} 2>&1`

          # Parse the JSON output
          # Bundler-Audit JSON output structure might vary, need to confirm
          # Assuming it returns a JSON object with vulnerability information
          parsed_output = JSON.parse(bundler_audit_output)
          # Extract the 'results' array from the parsed JSON
          parsed_output['results']
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