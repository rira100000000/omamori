# frozen_string_literal: true

require 'ruby_llm'

module Omamori
  module AIAnalysisEngine
    # Builds a RubyLLM context whose credentials come from each provider's usual environment variable
    # (GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, TYPESAFE_API_KEY, ...), overridden by `overrides`.
    module RubyLLMContext
      def self.build(overrides = {})
        RubyLLM.context do |config|
          config.public_methods.grep(/_api_(?:key|base)=\z/).each do |setter|
            value = ENV.fetch(setter.to_s.delete_suffix('=').upcase, nil)
            config.public_send(setter, value) if value
          end
          overrides.compact.each do |name, value|
            config.public_send("#{name}=", value) if config.respond_to?("#{name}=")
          end
        end
      end
    end
  end
end
