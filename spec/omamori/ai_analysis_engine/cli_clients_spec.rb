# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_analysis_engine/cli_clients/claude_code_client'
require 'omamori/ai_analysis_engine/cli_clients/codex_client'

RSpec.describe Omamori::AIAnalysisEngine::CLIClients::ClaudeCodeClient do
  let(:client) { described_class.new }
  let(:schema) { { type: 'object', properties: { security_risks: { type: 'array' } } } }
  let(:success) { instance_double(Process::Status, success?: true, exitstatus: 0) }
  let(:risks) { { 'security_risks' => [{ 'type' => 'xss' }] } }

  before { allow($stdout).to receive(:puts) }

  it 'runs claude -p with all tools disabled and returns the structured output' do
    expect(Open3).to receive(:capture3) do |*command, stdin_data:, chdir:|
      expect(command).to include('claude', '-p', '--json-schema', schema.to_json, '--model', 'sonnet')
      expect(command.each_cons(2)).to include(['--tools', ''])
      expect(stdin_data).to eq('prompt')
      expect(Dir.children(chdir)).to be_empty
      [{ is_error: false, structured_output: risks }.to_json, '', success]
    end

    expect(client.analyze('prompt', schema, model: 'sonnet')).to eq(risks)
  end

  it 'returns nil when claude reports an error' do
    allow(Open3).to receive(:capture3).and_return([{ is_error: true, result: 'limit reached' }.to_json, '', success])

    expect(client.analyze('prompt', schema)).to be_nil
  end

  it 'returns nil when the command fails' do
    failure = instance_double(Process::Status, success?: false, exitstatus: 1)
    allow(Open3).to receive(:capture3).and_return(['', 'not logged in', failure])

    expect(client.analyze('prompt', schema)).to be_nil
  end

  it 'returns nil when the command is not installed' do
    allow(Open3).to receive(:capture3).and_raise(Errno::ENOENT)

    expect(client.analyze('prompt', schema)).to be_nil
  end
end

RSpec.describe Omamori::AIAnalysisEngine::CLIClients::CodexClient do
  let(:client) { described_class.new }
  let(:schema) do
    { type: 'object', properties: { security_risks: { type: 'array', items: {
      type: 'object', properties: { type: { type: 'string' }, code_snippet: { type: 'string' } }, required: ['type']
    } } } }
  end
  let(:success) { instance_double(Process::Status, success?: true, exitstatus: 0) }
  let(:risks) { { 'security_risks' => [{ 'type' => 'xss', 'code_snippet' => '' }] } }

  before { allow($stdout).to receive(:puts) }

  it 'runs codex exec read-only with a strict schema and reads the last message' do
    expect(Open3).to receive(:capture3) do |*command, stdin_data:, **|
      expect(command.first(2)).to eq(%w[codex exec])
      expect(command.each_cons(2)).to include(['--sandbox', 'read-only'])
      expect(command.last).to eq('-')
      expect(stdin_data).to eq('prompt')

      written_schema = JSON.parse(File.read(command[command.index('--output-schema') + 1]))
      item = written_schema.dig('properties', 'security_risks', 'items')
      expect(item['required']).to eq(%w[type code_snippet])
      expect(item['additionalProperties']).to be(false)

      File.write(command[command.index('--output-last-message') + 1], risks.to_json)
      ['', '', success]
    end

    expect(client.analyze('prompt', schema)).to eq(risks)
  end

  it 'returns nil when codex writes no final message' do
    allow(Open3).to receive(:capture3).and_return(['', '', success])

    expect(client.analyze('prompt', schema)).to be_nil
  end
end
