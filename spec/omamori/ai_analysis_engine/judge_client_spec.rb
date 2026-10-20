# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_analysis_engine/judge_client'

RSpec.describe Omamori::AIAnalysisEngine::JudgeClient do
  let(:context) { instance_double(RubyLLM::Context) }
  let(:client) { described_class.new(context, provider: :typesafe, model: 'jev-1.13.0') }

  it 'asks every question as a probability and returns the probabilities by name' do
    answers = { xss: double('answer', probability: 0.8), csrf: double('refusal') }
    expect(context).to receive(:judge).with(
      'diff',
      questions: { xss: { type: :probability, instructions: 'xss?' },
                   csrf: { type: :probability, instructions: 'csrf?' } },
      model: 'jev-1.13.0', provider: :typesafe, assume_model_exists: true
    ).and_return(double('judgment', answers: answers))

    expect(client.classify('diff', xss: 'xss?', csrf: 'csrf?')).to eq(xss: 0.8, csrf: nil)
  end
end

RSpec.describe Omamori::AIAnalysisEngine::RubyLLMContext do
  it 'reads provider keys from their environment variables, overridden by explicit settings' do
    stub_const('ENV', ENV.to_h.merge('TYPESAFE_API_KEY' => 'from-env', 'GEMINI_API_KEY' => 'from-env'))

    config = described_class.build(gemini_api_key: 'from-config', openai_api_key: nil).config

    expect(config.typesafe_api_key).to eq('from-env')
    expect(config.gemini_api_key).to eq('from-config')
  end
end
