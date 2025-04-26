# frozen_string_literal: true

module Omamori
  module StaticAnalysers
    class BrakemanRunner
      def initialize(options = {})
        @options = options
      end

      def run
        puts "Running Brakeman..."
        # TODO: Determine Brakeman command based on options
        # Example: brakeman -f json .
        brakeman_command = "brakeman -f json ."

        begin
          # Execute the Brakeman command and capture output
          brakeman_output = `#{brakeman_command}`

          # Parse the JSON output
          JSON.parse(brakeman_output)
        rescue Errno::ENOENT
          puts "Error: Brakeman command not found. Is Brakeman installed?"
          nil
        rescue JSON::ParserError
          puts "Error: Failed to parse Brakeman JSON output."
          puts "Raw output:\n#{brakeman_output}"
          nil
        rescue => e
          puts "An error occurred during Brakeman execution: #{e.message}"
          nil
        end
      end
    end
  end
end