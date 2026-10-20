# frozen_string_literal: true

require_relative 'base'

module Omamori
  module AIAnalysisEngine
    module CLIClients
      # `codex exec` in a read-only sandbox with an output schema.
      class CodexClient < Base
        private

        def default_command
          'codex'
        end

        def build_command(dir, json_schema, model)
          schema_path = File.join(dir, 'schema.json')
          File.write(schema_path, JSON.generate(strict_schema(JSON.parse(json_schema.to_json))))
          command = [@command, 'exec', '--sandbox', 'read-only', '--skip-git-repo-check', '--ephemeral',
                     '--output-schema', schema_path, '--output-last-message', File.join(dir, 'last_message.json')]
          command += ['--model', model] if model
          command + ['-']
        end

        def parse(_output, dir)
          path = File.join(dir, 'last_message.json')
          File.exist?(path) ? JSON.parse(File.read(path)) : nil
        end

        # OpenAI structured outputs require every property to be required and no additional properties
        def strict_schema(schema)
          case schema
          when Hash
            strict = schema.transform_values { |value| strict_schema(value) }
            if strict['type'] == 'object' && strict['properties']
              strict['required'] = strict['properties'].keys
              strict['additionalProperties'] = false
            end
            strict
          when Array then schema.map { |value| strict_schema(value) }
          else schema
          end
        end
      end
    end
  end
end
