# frozen_string_literal: true

require 'gemini'

module Omamori
  module AIAnalysisEngine
    class GeminiClient
      def initialize(api_key)
        @api_key = api_key
        @client = nil # Initialize client later
      end

      def analyze(prompt, json_schema, model: "gemini-1.5-pro-latest")
        # Ensure the client is initialized
        client

        begin
          response = @client.generate_content(
            prompt,
            model: model,
            response_schema: json_schema # Use response_schema for Structured Output
          )

          # The response should be a StructuredOutput object if successful
          if response.is_a?(Gemini::Response::StructuredOutput)
            # Access the structured data
            response.data
          else
            # Handle cases where Structured Output is not returned or an error occurs
            puts "Warning: Structured Output not received or unexpected response format."
            puts "Raw response: #{response.inspect}"
            nil # Or raise an error, depending on desired behavior
          end
        rescue Faraday::Error => e
          puts "API Error: #{e.message}"
          puts "Response body: #{e.response[:body]}" if e.response
          nil # Handle API errors
        rescue => e
          puts "An unexpected error occurred during API call: #{e.message}"
          nil # Handle other errors
        end
      end

      private

      def client
        @client ||= begin
          # Configure the client with the API key
          Gemini.configure do |config|
            config.api_key = @api_key
          end
          # Create a new client instance
          Gemini::Client.new
        end
      end
    end
  end
end