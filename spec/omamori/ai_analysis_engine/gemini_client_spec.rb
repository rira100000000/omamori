# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_analysis_engine/gemini_client'
require 'gemini' # Use require 'gemini' to load the entire gem

RSpec.describe Omamori::AIAnalysisEngine::GeminiClient do
  let(:api_key) { 'test_api_key' }
  let(:model_name) { 'gemini-2.5-flash-preview-04-17' }
  let(:client_instance_double) { instance_double(Gemini::Client) }
  # Use instance_double with Gemini::Response
  let(:response_double) { instance_double(Gemini::Response) }

  before do
    # Mock the call to Gemini::Client.new
    allow(Gemini::Client).to receive(:new).and_return(client_instance_double)
    # Allow the call to Gemini.configure (will be verified in a separate test)
    allow(Gemini).to receive(:configure).and_call_original
  end

  describe '#initialize' do
    it 'stores the api_key' do
      client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
      expect(client.instance_variable_get(:@api_key)).to eq(api_key)
    end

    it 'initializes @client to nil' do
      client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
      expect(client.instance_variable_get(:@client)).to be_nil
    end
  end

  describe '#client' do
    it 'configures Gemini and creates a new client instance on first access' do
      client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)

      expect(Gemini).to receive(:configure).once
      expect(Gemini::Client).to receive(:new).once

      first_access = client.__send__(:client)
      second_access = client.__send__(:client) # Access again to check memoization

      expect(first_access).to eq(client_instance_double)
      expect(second_access).to eq(client_instance_double) # Should return the same instance
    end
  end

  describe '#analyze' do
    let(:prompt) { 'Analyze this code for security risks.' }
    let(:json_schema) { { type: 'object', properties: { security_risks: { type: 'array' } } } }
    let(:api_response_data) { { 'security_risks' => [{ 'type' => 'XSS', 'severity' => 'Medium' }] } }
    # Simulate the JSON response format from the API
    let(:api_response_text) { "```json\n#{api_response_data.to_json}```" }

    before do
      # Stub the call to the private client method to return the mocked client instance
      allow_any_instance_of(Omamori::AIAnalysisEngine::GeminiClient).to receive(:client).and_return(client_instance_double)
    end

    context 'when the API call is successful and returns valid structured output' do
      it 'calls generate_content with correct arguments and returns the parsed data' do
        allow(client_instance_double).to receive(:generate_content)
          .with(prompt, model: model_name, response_schema: json_schema, temperature: 0.0)
          .and_return(response_double)

        # Mock the response_double to return the simulated JSON text
        allow(response_double).to receive(:text).and_return(api_response_text)

        client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
        # Explicitly set the @client instance variable for the test
        result = client.analyze(prompt, json_schema, model: model_name)

        expect(result).to eq(api_response_data)
      end
    end

    context 'when the API call is successful but returns invalid JSON' do
      it 'returns nil and prints a warning' do
        allow(client_instance_double).to receive(:generate_content)
          .and_return(response_double)

        # Simulate invalid JSON response text
        invalid_json_text = 'This is not JSON'
        allow(response_double).to receive(:text).and_return(invalid_json_text)

        client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
        expect do
          result = client.analyze(prompt, json_schema, model: model_name)
          expect(result).to be_nil
        end.to output(/Warning: Failed to parse response text as JSON.\nRaw response text: #{Regexp.escape(invalid_json_text)}/).to_stdout
      end
    end

    context 'when a Faraday::Error occurs during the API call' do
      it 'returns nil and prints an API error message' do
        # Mock Faraday::Response to return a hash-like object for body
        response_double = instance_double(Faraday::Response, status: 500)
        allow(response_double).to receive(:[]).with(:body).and_return('Error details')

        # Create a real Faraday::Error instance with the mocked response
        api_error = Faraday::Error.new('API error occurred', response: response_double)
        allow(client_instance_double).to receive(:generate_content).and_raise(api_error)

        client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
        expect do
          result = client.analyze(prompt, json_schema, model: model_name)
          expect(result).to be_nil
        end.to output(/API Error: API error occurred\nResponse body: \n/).to_stdout
      end
    end

    context 'when an unexpected error occurs during the API call' do
      it 'returns nil and prints a generic error message' do
        unexpected_error = StandardError.new('Something went wrong')
        allow(client_instance_double).to receive(:generate_content).and_raise(unexpected_error)

        client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
        expect do
          result = client.analyze(prompt, json_schema, model: model_name)
          expect(result).to be_nil
        end.to output(/An unexpected error occurred during API call: Something went wrong/).to_stdout
      end
    end
  end
end
