# frozen_string_literal: true

require 'spec_helper'
require 'yaml'
require 'omamori/setup_files'

RSpec.describe Omamori::SetupFiles do
  def settings(overrides)
    empty_config = Struct.new(:values) { def get(key, default = nil) = values.fetch(key.to_s, default) }.new({})
    Omamori::AISettings.new(empty_config, overrides)
  end

  let(:cli_settings) { settings(reporter: 'claude_code', reporter_model: 'sonnet', classifier: 'typesafe') }
  let(:api_settings) { settings(reporter: 'anthropic', reporter_model: 'claude-sonnet-5-5') }

  describe '.omamorirc' do
    it 'writes the chosen roles as YAML that AISettings reads back' do
      config = YAML.safe_load(described_class.omamorirc(cli_settings, language: 'ja'))

      expect(config).to eq('reporter' => { 'provider' => 'claude_code', 'model' => 'sonnet' },
                           'classifier' => { 'provider' => 'typesafe', 'model' => 'jev-1.13.0' },
                           'language' => 'ja')
    end

    it 'leaves the classifier and language commented out when not chosen' do
      config = YAML.safe_load(described_class.omamorirc(api_settings))

      expect(config).to eq('reporter' => { 'provider' => 'anthropic', 'model' => 'claude-sonnet-5-5' })
    end

    it 'writes the fallback reporter under the reporter' do
      s = settings(reporter: 'anthropic', reporter_model: 'claude-x', reporter_fallback: 'claude_code')

      expect(YAML.safe_load(described_class.omamorirc(s))['reporter'])
        .to eq('provider' => 'anthropic', 'model' => 'claude-x', 'fallback' => { 'provider' => 'claude_code' })
    end
  end

  describe '.github_actions' do
    it 'passes the API keys each role needs' do
      steps = YAML.safe_load(described_class.github_actions(api_settings))['jobs']['security_scan']['steps']

      expect(steps.last['env'].keys).to eq(%w[ANTHROPIC_API_KEY])
    end

    it 'does not install a subscription CLI, and says so' do
      content = described_class.github_actions(cli_settings)
      steps = YAML.safe_load(content)['jobs']['security_scan']['steps']

      expect(steps.map { |step| step['name'] }).to eq(['Checkout code', 'Set up Ruby', 'Run Omamori Scan'])
      expect(steps.last['env'].keys).to eq(%w[TYPESAFE_API_KEY])
      expect(content).to include('does not do')
    end
  end

  describe '.gitlab_ci' do
    it 'is valid YAML that lists the variables to set' do
      content = described_class.gitlab_ci(cli_settings)

      expect(YAML.safe_load(content)['omamori_security_scan']['before_script'].join).not_to include('npm')
      expect(content).to include('# TYPESAFE_API_KEY')
    end
  end

  describe '.credential_steps' do
    it 'says what to set up for each role' do
      expect(described_class.credential_steps(cli_settings))
        .to eq(['classifier: set TYPESAFE_API_KEY',
                'reporter: install Claude Code and log in (`claude`), or set ANTHROPIC_API_KEY'])
    end
  end
end
