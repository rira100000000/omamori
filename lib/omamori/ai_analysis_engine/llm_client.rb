# frozen_string_literal: true

require 'json'
require_relative 'ruby_llm_context'

module Omamori
  module AIAnalysisEngine
    # Asks any RubyLLM chat model for a structured security report.
    class LLMClient
      DEFAULT_MODEL = 'gemini-3.8-flash'
      EMPTY_RESPONSE_RETRIES = 2
      # Finish reasons that mean the model refused; asking again gives the same result
      REFUSAL_REASONS = %i[other safety prohibited_content blocklist spii recitation refusal content_filter].freeze

      def initialize(context, provider: nil)
        @context = context
        @provider = provider
      end

      # Returns the parsed JSON (a Hash with 'security_risks') or nil
      def analyze(prompt, json_schema, model: DEFAULT_MODEL)
        response = ask_with_text(prompt, json_schema, model)
        return nil unless response

        parsed = JSON.parse(response.content.gsub(/\A```json\n|```\z/, '').strip)
        return parsed if parsed.is_a?(Hash) && parsed.key?('security_risks')

        puts 'Warning: Unexpected AI analysis response structure.'
        puts "Raw response text: #{response.content}"
        nil
      rescue JSON::ParserError
        puts 'Warning: Failed to parse response text as JSON.'
        puts "Raw response text: #{response.content}"
        nil
      rescue RubyLLM::Error => e
        puts "API Error: #{e.message}"
        nil
      rescue StandardError => e
        puts "An unexpected error occurred during API call: #{e.message}"
        nil
      end

      private

      # Models occasionally return an empty response. Retry a couple of times before giving up,
      # unless the model refused: an unchecked chunk must not look like a clean result.
      def ask_with_text(prompt, json_schema, model)
        (EMPTY_RESPONSE_RETRIES + 1).times do
          response = chat(model).with_schema(json_schema).ask(prompt)
          return response unless response.content.to_s.strip.empty?

          reason = response.finish_reason
          if REFUSAL_REASONS.include?(reason.to_s.downcase.to_sym)
            puts "Warning: The model refused to analyze this content (finish reason: #{reason}). It was NOT checked."
            return nil
          end

          puts "Warning: Empty AI response (finish reason: #{reason || 'unknown'}). Retrying..."
        end
        puts 'Warning: AI returned no text after retries.'
        nil
      end

      def chat(model)
        return @context.chat(model: model) unless @provider

        @context.chat(model: model, provider: @provider, assume_model_exists: true)
      end
    end
  end
end
