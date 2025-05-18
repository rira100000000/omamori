# frozen_string_literal: true

module Omamori
  module StaticAnalysers
    class BrakemanRunner
      def initialize(options = {})
        @options = options
      end

      def run
        puts 'Running Brakeman...'
        # Determine Brakeman command based on options
        # Use --force to run scan even if it's not a Rails application
        # Use -f json for JSON output
        # Include options passed during initialization
        # Convert options hash to command line arguments string
        options_string = @options.map do |key, value|
          if value.is_a?(TrueClass)
            key.to_s
          elsif value.is_a?(FalseClass)
            '' # Don't include false flags
          else
            "#{key} #{value}"
          end
        end.join(' ').strip

        brakeman_command = "brakeman -f json . --force #{options_string}".strip # strip again in case options_string is empty

        begin
          # Execute the Brakeman command and capture output
          brakeman_output = `#{brakeman_command}`

          # Parse the JSON output
          # Note: JSON.parse is called here. If the test expects it to be called only once,
          # the test setup might be causing it to be called multiple times or the mock is misconfigured.
          JSON.parse(brakeman_output)
        rescue Errno::ENOENT
          puts 'Error: Brakeman command not found. Is Brakeman installed?'
          nil
        rescue JSON::ParserError
          puts 'Error: Failed to parse Brakeman JSON output.'
          puts "Raw output:\n#{brakeman_output}"
          nil
        rescue StandardError => e
          puts "An error occurred during Brakeman execution: #{e.message}"
          nil
        end
      end
    end
  end
end
