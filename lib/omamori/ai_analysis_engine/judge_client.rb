# frozen_string_literal: true

require_relative 'ruby_llm_context'

module Omamori
  module AIAnalysisEngine
    # Asks a decision model (TypeSafe Jev, OpenAI Decisions, ...) yes/no questions through RubyLLM.judge.
    class JudgeClient
      ENGINES = {
        jev: { provider: :typesafe, model: 'jev-1.13.0' },
        openai: { provider: :openai, model: 'gpt-6-luna' }
      }.freeze

      def initialize(context, provider:, model:)
        @context = context
        @provider = provider
        @model = model
      end

      # questions: { name => instructions }
      # Returns { name => probability that the answer is yes, or nil when the model gave none (e.g. a refusal) }
      def classify(state, questions)
        judgment = @context.judge(
          state,
          questions: questions.transform_values { |instructions| { type: :probability, instructions: instructions } },
          model: @model, provider: @provider, assume_model_exists: true
        )
        questions.keys.to_h do |name|
          answer = judgment.answers[name]
          [name, answer.respond_to?(:probability) ? answer.probability : nil]
        end
      end
    end
  end
end
