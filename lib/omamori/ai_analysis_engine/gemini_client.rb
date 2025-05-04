# frozen_string_literal: true

require 'gemini'

module Omamori
  module AIAnalysisEngine
    class GeminiClient
      def initialize(api_key)
        @api_key = api_key || ENV["GEMINI_API_KEY"]
        @client = nil # Initialize client later
      end

      def analyze(prompt, json_schema, model: "gemini-1.5-pro-latest")
        # Ensure the client is initialized
        client

        begin
          response = @client.generate_content(
            prompt,
            model: model,
            response_schema: json_schema, # Use response_schema for Structured Output
            temperature: 0.0
          )

          # Debug: Inspect the response object
          # puts "Debug: response object: #{response.inspect}"
          # puts "Debug: response methods: #{response.methods.sort}"

          # Extract and parse JSON from the response text
          json_string = response.text.gsub(/\A```json\n|```\z/, '').strip
          begin
            parsed_response = JSON.parse(json_string)
            # Validate the parsed output structure
            if parsed_response.is_a?(Hash) && parsed_response.key?('security_risks')
              # Return the parsed JSON data
              parsed_response
            else
              puts "Warning: Unexpected AI analysis response structure."
              puts "Raw response text: #{response.text}"
              nil # Return nil if the structure is unexpected
            end
          rescue JSON::ParserError
            puts "Warning: Failed to parse response text as JSON."
            puts "Raw response text: #{response.text}"
            nil # Or handle the error appropriately
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