# frozen_string_literal: true

module Omamori
  module AIAnalysisEngine
    # Asks the primary reporter, and the fallback reporter only when the primary gives no answer
    # (a refusal, an error, or an unusable response). Same interface as LLMClient#analyze.
    class FallbackClient
      def initialize(primary, fallback, fallback_model:)
        @primary = primary
        @fallback = fallback
        @fallback_model = fallback_model
      end

      def analyze(prompt, json_schema, model: nil)
        result = @primary.analyze(prompt, json_schema, model: model)
        return result if result

        puts 'Asking the fallback reporter...'
        @fallback.analyze(prompt, json_schema, model: @fallback_model)
      end
    end
  end
end
