# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_analysis_engine/gemini_client'

RSpec.describe Omamori::AIAnalysisEngine::GeminiClient do
  let(:api_key) { "test_api_key" }
  let(:model_name) { "gemini-1.5-pro-latest" }
  let(:client_instance_double) { instance_double(Gemini::Client) }
  let(:structured_output_double) { instance_double(Gemini::Response::StructuredOutput) }

  before do
    # Gemini::Client.newの呼び出しをモック
    allow(Gemini::Client).to receive(:new).and_return(client_instance_double)
    # Gemini.configureの呼び出しを許可 (テスト内で検証)
    allow(Gemini).to receive(:configure).and_call_original
  end

  describe "#initialize" do
    it "stores the api_key" do
      client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
      expect(client.instance_variable_get(:@api_key)).to eq(api_key)
    end

    it "initializes @client to nil" do
      client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
      expect(client.instance_variable_get(:@client)).to be_nil
    end
  end

  describe "#client" do
    it "configures Gemini and creates a new client instance on first access" do
      client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)

      expect(Gemini).to receive(:configure).once
      expect(Gemini::Client).to receive(:new).once

      first_access = client.__send__(:client)
      second_access = client.__send__(:client) # Access again to check memoization

      expect(first_access).to eq(client_instance_double)
      expect(second_access).to eq(client_instance_double) # Should return the same instance
    end
  end

  describe "#analyze" do
    let(:prompt) { "Analyze this code for security risks." }
    let(:json_schema) { { type: "object", properties: { security_risks: { type: "array" } } } }
    let(:api_response_data) { { "security_risks" => [{ "risk" => "XSS", "severity" => "Medium" }] } }

    before do
      # analyzeメソッド内で呼ばれるclientメソッドをスタブし、モックしたclient_instance_doubleを返すように設定
      allow_any_instance_of(Omamori::AIAnalysisEngine::GeminiClient).to receive(:client).and_return(client_instance_double)
    end

    context "when the API call is successful and returns StructuredOutput" do
      it "calls generate_content with correct arguments and returns the structured data" do
        allow(client_instance_double).to receive(:generate_content)
          .with(prompt, model: model_name, response_schema: json_schema)
          .and_return(structured_output_double)

        allow(structured_output_double).to receive(:is_a?).with(Gemini::Response::StructuredOutput).and_return(true)
        allow(structured_output_double).to receive(:data).and_return(api_response_data)

        client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
        result = client.analyze(prompt, json_schema, model: model_name)

        expect(result).to eq(api_response_data)
      end
    end

    context "when the API call returns non-StructuredOutput" do
      it "returns nil and prints a warning" do
        allow(client_instance_double).to receive(:generate_content)
          .and_return("unexpected response string") # Simulate unexpected response

        allow_any_instance_of(String).to receive(:is_a?).with(Gemini::Response::StructuredOutput).and_return(false)

        client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
        expect {
          result = client.analyze(prompt, json_schema, model: model_name)
          expect(result).to be_nil
        }.to output(/Warning: Structured Output not received or unexpected response format./).to_stdout
      end
    end

    context "when a Faraday::Error occurs during the API call" do
      it "returns nil and prints an API error message" do
        api_error = Faraday::Error.new("API error occurred", response: { status: 500, body: "Error details" })
        allow(client_instance_double).to receive(:generate_content).and_raise(api_error)

        client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
        expect {
          result = client.analyze(prompt, json_schema, model: model_name)
          expect(result).to be_nil
        }.to output(/API Error: API error occurred\nResponse body: Error details/).to_stdout
      end
    end

    context "when an unexpected error occurs during the API call" do
      it "returns nil and prints a generic error message" do
        unexpected_error = StandardError.new("Something went wrong")
        allow(client_instance_double).to receive(:generate_content).and_raise(unexpected_error)

        client = Omamori::AIAnalysisEngine::GeminiClient.new(api_key)
        expect {
          result = client.analyze(prompt, json_schema, model: model_name)
          expect(result).to be_nil
        }.to output(/An unexpected error occurred during API call: Something went wrong/).to_stdout
      end
    end
  end
end