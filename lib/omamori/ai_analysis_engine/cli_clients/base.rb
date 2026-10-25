# frozen_string_literal: true

require 'json'
require 'open3'
require 'tmpdir'

module Omamori
  module AIAnalysisEngine
    module CLIClients
      # Runs an agent CLI as a plain LLM so it can use the user's subscription.
      # The prompt contains untrusted code, so every CLI runs in an empty directory with tools disabled
      # or a read-only sandbox.
      class Base
        def initialize(command: nil)
          @command = command || default_command
        end

        # Same interface as LLMClient#analyze. Returns the parsed JSON or nil.
        def analyze(prompt, json_schema, model: nil)
          Dir.mktmpdir('omamori-llm') do |dir|
            output, error, status = Open3.capture3(*build_command(dir, json_schema, model), stdin_data: prompt, chdir: dir)
            unless status.success?
              puts "Warning: #{@command} exited with #{status.exitstatus}: #{error.strip[0, 500]}"
              return nil
            end

            result = parse(output, dir)
            return result if result.is_a?(Hash) && result.key?('security_risks')

            puts "Warning: Unexpected response from #{@command}."
            nil
          end
        rescue Errno::ENOENT
          puts "Warning: '#{@command}' command not found. Install it or choose another --llm."
          nil
        rescue JSON::ParserError => e
          puts "Warning: Failed to parse the response from #{@command}: #{e.message}"
          nil
        end
      end
    end
  end
end
