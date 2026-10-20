# frozen_string_literal: true

require_relative 'base'

module Omamori
  module AIAnalysisEngine
    module CLIClients
      # `claude -p` (Claude Code) with all tools disabled and structured output.
      class ClaudeCodeClient < Base
        private

        def default_command
          'claude'
        end

        def build_command(_dir, json_schema, model)
          command = [@command, '-p', '--tools', '', '--strict-mcp-config', '--no-session-persistence',
                     '--output-format', 'json', '--json-schema', json_schema.to_json]
          command += ['--model', model] if model
          command
        end

        def parse(output, _dir)
          response = JSON.parse(output)
          if response['is_error']
            puts "Warning: claude returned an error: #{response['result'].to_s[0, 500]}"
            return nil
          end

          response['structured_output'] || JSON.parse(response['result'].to_s)
        end
      end
    end
  end
end
