# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_analysis_engine/llm_client'

RSpec.describe Omamori::AIAnalysisEngine::LLMClient do
  let(:context) { instance_double(RubyLLM::Context) }
  let(:chat) { instance_double(RubyLLM::Chat) }
  let(:schema) { { type: 'object' } }
  let(:risks) { { 'security_risks' => [{ 'type' => 'XSS' }] } }
  let(:client) { described_class.new(context) }

  def message(content, finish_reason: :stop)
    instance_double(RubyLLM::Message, content: content, finish_reason: finish_reason)
  end

  before do
    allow($stdout).to receive(:puts)
    allow(context).to receive(:chat).and_return(chat)
    allow(chat).to receive(:with_schema).with(schema).and_return(chat)
  end

  it 'asks the model with the schema and returns the parsed report' do
    expect(context).to receive(:chat).with(model: 'gemini-test').and_return(chat)
    allow(chat).to receive(:ask).with('prompt').and_return(message(risks.to_json))

    expect(client.analyze('prompt', schema, model: 'gemini-test')).to eq(risks)
  end

  it 'uses the configured provider without a registry lookup' do
    client = described_class.new(context, provider: :anthropic)
    expect(context).to receive(:chat).with(model: 'claude-x', provider: :anthropic, assume_model_exists: true)
                                     .and_return(chat)
    allow(chat).to receive(:ask).and_return(message(risks.to_json))

    expect(client.analyze('prompt', schema, model: 'claude-x')).to eq(risks)
  end

  it 'retries an empty response' do
    allow(chat).to receive(:ask).and_return(message(''), message(risks.to_json))

    expect(client.analyze('prompt', schema)).to eq(risks)
  end

  it 'does not retry a refusal and warns that the content was not checked' do
    allow(chat).to receive(:ask).and_return(message('', finish_reason: :OTHER))

    expect { expect(client.analyze('prompt', schema)).to be_nil }.to output(/It was NOT checked/).to_stdout
    expect(chat).to have_received(:ask).once
  end

  it 'gives up after the retries' do
    allow(chat).to receive(:ask).and_return(message(''))

    expect(client.analyze('prompt', schema)).to be_nil
    expect(chat).to have_received(:ask).exactly(3).times
  end

  it 'returns nil for invalid JSON or an API error' do
    allow(chat).to receive(:ask).and_return(message('not json'))
    expect(client.analyze('prompt', schema)).to be_nil

    allow(chat).to receive(:ask).and_raise(RubyLLM::Error.new('quota exceeded'))
    expect(client.analyze('prompt', schema)).to be_nil
  end
end
