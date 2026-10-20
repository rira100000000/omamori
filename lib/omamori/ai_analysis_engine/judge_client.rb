# frozen_string_literal: true

require_relative 'ruby_llm_context'

module Omamori
  module AIAnalysisEngine
    # Asks a decision model (TypeSafe Jev, OpenAI Decisions, ...) yes/no questions through RubyLLM.judge.
    class JudgeClient
      # Input tokens used so far, across threads
      attr_reader :input_tokens

      # max_questions: split larger question sets into several requests (OpenAI accepts up to 200 per request)
      def initialize(context, provider:, model:, max_questions: nil)
        @context = context
        @provider = provider
        @model = model
        @max_questions = max_questions
        @input_tokens = 0
        @mutex = Mutex.new
      end

      # questions: { name => instructions }
      # Returns { name => probability that the answer is yes, or nil when the model gave none (e.g. a refusal) }
      def classify(state, questions)
        batches = @max_questions ? questions.each_slice(@max_questions).map(&:to_h) : [questions]
        batches.map { |batch| judge(state, batch) }.reduce({}, :merge)
      end

      private

      def judge(state, questions)
        judgment = @context.judge(
          state,
          questions: questions.transform_values { |instructions| { type: :probability, instructions: instructions } },
          model: @model, provider: @provider, assume_model_exists: true
        )
        @mutex.synchronize { @input_tokens += judgment.tokens&.input.to_i }
        questions.keys.to_h do |name|
          answer = judgment.answers[name]
          [name, answer.respond_to?(:probability) ? answer.probability : nil]
        end
      end
    end
  end
end
