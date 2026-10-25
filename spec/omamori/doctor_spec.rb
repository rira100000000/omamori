# frozen_string_literal: true

require 'spec_helper'
require 'omamori/doctor'

RSpec.describe Omamori::Doctor do
  let(:reporter) { { 'provider' => 'anthropic', 'model' => 'claude-x' } }
  let(:reporter_client) { double('reporter client') }
  let(:settings) do
    instance_double(Omamori::AISettings, describe: 'reporter: anthropic/claude-x', classifier?: false,
                                         reporter: reporter, reporter_fallback: nil)
  end

  before { allow(settings).to receive(:build_llm_client).with(reporter).and_return(reporter_client) }

  def run_doctor
    result = nil
    expect { result = described_class.new(settings, json_schema: {}).run }.to output.to_stdout
    result
  end

  it 'passes when the reporter answers' do
    allow(reporter_client).to receive(:analyze).and_return({ 'security_risks' => [] })

    expect(run_doctor).to be(true)
  end

  it 'fails and names the missing environment variable when the reporter gives nothing' do
    allow(reporter_client).to receive(:analyze).and_return(nil)
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('ANTHROPIC_API_KEY').and_return(nil)

    expect { described_class.new(settings, json_schema: {}).run }.to output(/ANTHROPIC_API_KEY is not set/).to_stdout
  end

  it 'fails before sending anything when the CLI is missing' do
    cli = { 'provider' => 'claude_code', 'command' => '/nonexistent/claude' }
    allow(settings).to receive(:reporter).and_return(cli)

    expect { expect(described_class.new(settings, json_schema: {}).run).to be(false) }
      .to output(%r{'/nonexistent/claude' was not found}).to_stdout
  end
end
