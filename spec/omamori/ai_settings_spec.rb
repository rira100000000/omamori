# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_settings'

RSpec.describe Omamori::AISettings do
  # Config only needs #get
  def config(hash)
    Struct.new(:values) { def get(key, default = nil) = values.fetch(key.to_s, default) }.new(hash)
  end

  def settings(hash = {}, overrides = {})
    described_class.new(config(hash), overrides)
  end

  describe 'defaults' do
    it 'uses no classifier and Gemini as the reporter' do
      s = settings

      expect(s.classifier?).to be(false)
      expect(s.reporter).to eq('provider' => 'gemini', 'model' => 'gemini-3.8-flash')
      expect(s.reporter_concurrency).to eq(8)
    end
  end

  describe 'classifier and reporter keys' do
    it 'reads provider and model for each role' do
      s = settings('classifier' => { 'provider' => 'typesafe', 'model' => 'jev-1.14.0', 'threshold' => 0.5 },
                   'reporter' => { 'provider' => 'anthropic', 'model' => 'claude-sonnet-5-5' })

      expect(s.classifier).to include('provider' => 'typesafe', 'model' => 'jev-1.14.0')
      expect(s.threshold).to eq(0.5)
      expect(s.classifier_concurrency).to eq(8)
      expect(s.reporter).to eq('provider' => 'anthropic', 'model' => 'claude-sonnet-5-5')
      expect(s.describe).to eq('classifier: typesafe/jev-1.14.0, reporter: anthropic/claude-sonnet-5-5')
    end

    it 'fills in the default model for typesafe and openai classifiers' do
      expect(settings('classifier' => { 'provider' => 'typesafe' }).classifier['model']).to eq('jev-1.13.0')
      expect(settings('classifier' => { 'provider' => 'openai' }).classifier['model']).to eq('gpt-6-luna')
    end

    it 'lets the model alone choose the reporter provider' do
      expect(settings('reporter' => { 'model' => 'claude-sonnet-5-5' }).reporter).to eq('model' => 'claude-sonnet-5-5')
    end

    it 'treats claude_code and codex as subscription CLIs' do
      s = settings('reporter' => { 'provider' => 'claude_code', 'model' => 'sonnet' })

      expect(s.cli_reporter?).to be(true)
      expect(s.reporter_concurrency).to eq(3)
      expect(s.build_reporter_client).to be_a(Omamori::AIAnalysisEngine::CLIClients::ClaudeCodeClient)
    end

    it 'builds RubyLLM clients for API providers' do
      s = settings('classifier' => { 'provider' => 'typesafe' })

      expect(s.build_classifier_client).to be_a(Omamori::AIAnalysisEngine::JudgeClient)
      expect(s.build_reporter_client).to be_a(Omamori::AIAnalysisEngine::LLMClient)
    end

    it "passes each role's api_key and base_url to RubyLLM" do
      s = settings('classifier' => { 'provider' => 'typesafe', 'api_key' => 'ts-key', 'base_url' => 'http://localhost:8000' },
                   'reporter' => { 'provider' => 'anthropic', 'model' => 'claude-x', 'api_key' => 'an-key' })
      context = s.__send__(:ruby_llm_context)

      expect(context.config.typesafe_api_key).to eq('ts-key')
      expect(context.config.typesafe_api_base).to eq('http://localhost:8000')
      expect(context.config.anthropic_api_key).to eq('an-key')
    end
  end

  describe 'older keys' do
    it 'reads engine, decision, model, and api_key' do
      s = settings('engine' => 'jev', 'model' => 'gemini-3.5-flash', 'api_key' => 'gm-key',
                   'decision' => { 'threshold' => 0.4, 'concurrency' => 4, 'report_concurrency' => 2,
                                   'jev' => { 'model' => 'jev-1.14.0', 'base_url' => 'http://kev.local' } })

      expect(s.classifier).to include('provider' => 'typesafe', 'model' => 'jev-1.14.0', 'base_url' => 'http://kev.local')
      expect(s.threshold).to eq(0.4)
      expect(s.classifier_concurrency).to eq(4)
      expect(s.reporter).to eq('model' => 'gemini-3.5-flash', 'concurrency' => 2)
      expect(s.__send__(:ruby_llm_context).config.gemini_api_key).to eq('gm-key')
    end

    it 'reads engine: gemini / llm as no classifier' do
      expect(settings('engine' => 'gemini').classifier?).to be(false)
      expect(settings('engine' => 'llm').classifier?).to be(false)
    end

    it 'reads llm: claude with its own settings' do
      s = settings('llm' => 'claude', 'claude' => { 'model' => 'sonnet', 'command' => '/opt/claude' })

      expect(s.reporter).to eq('provider' => 'claude_code', 'model' => 'sonnet', 'command' => '/opt/claude')
    end
  end

  describe 'command-line overrides' do
    it 'replaces the provider and drops the configured model of another provider' do
      s = settings({ 'classifier' => { 'provider' => 'typesafe', 'model' => 'jev-1.14.0', 'threshold' => 0.5 } },
                   classifier: 'openai')

      expect(s.classifier).to eq('provider' => 'openai', 'model' => 'gpt-6-luna')
    end

    it 'keeps the configured settings when the provider is the same' do
      s = settings({ 'classifier' => { 'provider' => 'typesafe', 'threshold' => 0.5 } },
                   classifier: 'typesafe', classifier_model: 'jev-preview')

      expect(s.classifier).to include('model' => 'jev-preview', 'threshold' => 0.5)
    end

    it 'turns the classifier off with none' do
      expect(settings({ 'classifier' => { 'provider' => 'typesafe' } }, classifier: 'none').classifier?).to be(false)
    end

    it 'switches the reporter' do
      s = settings({ 'reporter' => { 'provider' => 'anthropic', 'model' => 'claude-x' } },
                   reporter: 'gemini', reporter_model: 'gemini-3.5-flash')

      expect(s.reporter).to eq('provider' => 'gemini', 'model' => 'gemini-3.5-flash')
    end
  end

  describe 'errors' do
    it 'rejects an unknown classifier provider' do
      expect { settings('classifier' => { 'provider' => 'nope' }) }.to raise_error(described_class::Error, /Unknown/)
    end

    it 'rejects a provider that cannot classify' do
      expect { settings('classifier' => { 'provider' => 'gemini' }) }
        .to raise_error(described_class::Error, /cannot be used as a classifier/)
    end

    it 'requires a model when the classifier provider has no default' do
      expect { settings('classifier' => { 'provider' => 'ollama' }) }
        .to raise_error(described_class::Error, /classifier.model is required/)
    end

    it 'rejects an unknown reporter provider, and requires its model' do
      expect { settings('reporter' => { 'provider' => 'nope', 'model' => 'x' }) }
        .to raise_error(described_class::Error, /Unknown reporter provider/)
      expect { settings('reporter' => { 'provider' => 'anthropic' }) }
        .to raise_error(described_class::Error, /reporter.model is required/)
    end

    it 'rejects an unknown legacy engine' do
      expect { settings('engine' => 'nope') }.to raise_error(described_class::Error, /Unknown engine/)
    end
  end
end
