# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_analysis_engine/checklist_scanner'
require 'omamori/ai_analysis_engine/diff_splitter'
require 'omamori/ai_analysis_engine/llm_client'
require 'omamori/ai_analysis_engine/prompt_manager'

RSpec.describe Omamori::AIAnalysisEngine::ChecklistScanner do
  let(:decision_client) { double('decision_client') }
  let(:llm_client) { instance_double(Omamori::AIAnalysisEngine::LLMClient) }
  let(:prompt_manager) { instance_double(Omamori::AIAnalysisEngine::PromptManager) }
  let(:diff_splitter) { Omamori::AIAnalysisEngine::DiffSplitter.new(chunk_size: 10_000) }
  let(:json_schema) { { type: 'object' } }
  let(:scanner) do
    described_class.new(decision_client: decision_client, llm_client: llm_client,
                        prompt_manager: prompt_manager, diff_splitter: diff_splitter,
                        json_schema: json_schema, model: 'gemini-test', threshold: 0.5, concurrency: 2)
  end
  let(:units) { [['app/a.rb', 'diff a'], ['app/b.rb', 'diff b']] }

  before do
    allow($stdout).to receive(:puts)
    allow(prompt_manager).to receive(:build_question) { |risk| "question #{risk}" }
    allow(prompt_manager).to receive(:build_prompt) { |content, risks, *| "prompt #{content} #{risks.join}" }
    stub_const("#{described_class}::SINGLE_RISK_INSTRUCTION", '')
  end

  it 'sends every risk as a question for each unit in one request' do
    expect(decision_client).to receive(:classify)
      .with('diff a', { xss: 'question xss', csrf: 'question csrf' }).and_return(xss: 0.1, csrf: 0.1)
    expect(decision_client).to receive(:classify)
      .with('diff b', { xss: 'question xss', csrf: 'question csrf' }).and_return(xss: 0.1, csrf: 0.1)
    expect(llm_client).not_to receive(:analyze)

    expect(scanner.scan(units, %i[xss csrf])).to eq('security_risks' => [])
  end

  it 'asks Gemini for a report only for checks at or above the threshold' do
    allow(decision_client).to receive(:classify).with('diff a', anything).and_return(xss: 0.9, csrf: 0.1)
    allow(decision_client).to receive(:classify).with('diff b', anything).and_return(xss: 0.2, csrf: 0.5)
    expect(llm_client).to receive(:analyze).with('prompt diff a xss', json_schema, model: 'gemini-test')
                                              .and_return('security_risks' => [{ 'type' => 'XSS' }])
    expect(llm_client).to receive(:analyze).with('prompt diff b csrf', json_schema, model: 'gemini-test')
                                              .and_return('security_risks' => [{ 'type' => 'CSRF' }])

    result = scanner.scan(units, %i[xss csrf])
    expect(result['security_risks']).to contain_exactly({ 'type' => 'XSS' }, { 'type' => 'CSRF' })
  end

  it 'escalates every check of a unit when the decision API fails' do
    allow(decision_client).to receive(:classify).with('diff a', anything).and_raise('boom')
    allow(decision_client).to receive(:classify).with('diff b', anything).and_return(xss: 0.0)
    expect(llm_client).to receive(:analyze).once.and_return('security_risks' => [])

    expect(scanner.scan(units, %i[xss])).to eq('security_risks' => [])
  end

  it 'keeps the flag when Gemini cannot write a report' do
    allow(decision_client).to receive(:classify).and_return(xss: 0.8)
    allow(llm_client).to receive(:analyze).and_return(nil)

    risks = scanner.scan([['app/a.rb', 'diff a']], %i[xss])['security_risks']
    expect(risks).to contain_exactly(include('type' => 'xss', 'location' => 'app/a.rb', 'severity' => 'Info'))
  end

  it 'splits a unit larger than the chunk size' do
    small_splitter = Omamori::AIAnalysisEngine::DiffSplitter.new(chunk_size: 10)
    scanner = described_class.new(decision_client: decision_client, llm_client: llm_client,
                                  prompt_manager: prompt_manager, diff_splitter: small_splitter,
                                  json_schema: json_schema, model: 'gemini-test')
    expect(decision_client).to receive(:classify).twice.and_return(xss: 0.0)

    scanner.scan([['big.rb', "line one\nline two\n"]], %i[xss])
  end
end
