# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_analysis_engine/fallback_client'

RSpec.describe Omamori::AIAnalysisEngine::FallbackClient do
  let(:primary) { double('primary') }
  let(:fallback) { double('fallback') }
  let(:client) { described_class.new(primary, fallback, fallback_model: 'sonnet') }
  let(:report) { { 'security_risks' => [] } }

  before { allow($stdout).to receive(:puts) }

  it 'uses the primary answer when there is one' do
    expect(primary).to receive(:analyze).with('prompt', {}, model: 'gemini-x').and_return(report)
    expect(fallback).not_to receive(:analyze)

    expect(client.analyze('prompt', {}, model: 'gemini-x')).to eq(report)
  end

  it 'asks the fallback with its own model when the primary gives no answer' do
    allow(primary).to receive(:analyze).and_return(nil)
    expect(fallback).to receive(:analyze).with('prompt', {}, model: 'sonnet').and_return(report)

    expect(client.analyze('prompt', {}, model: 'gemini-x')).to eq(report)
  end
end
