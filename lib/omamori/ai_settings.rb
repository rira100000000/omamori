# frozen_string_literal: true

require_relative 'ai_analysis_engine/ruby_llm_context'
require_relative 'ai_analysis_engine/llm_client'
require_relative 'ai_analysis_engine/judge_client'
require_relative 'ai_analysis_engine/cli_clients/claude_code_client'
require_relative 'ai_analysis_engine/cli_clients/codex_client'

module Omamori
  # Decides which classifier and reporter to use, from .omamorirc and command-line options.
  #
  #   classifier:            # omit to let the reporter check everything itself
  #     provider: typesafe   # any RubyLLM provider that can judge (typesafe, openai, ollama)
  #     model: jev-1.13.0
  #   reporter:
  #     provider: anthropic  # any RubyLLM provider, or claude_code / codex (subscription CLIs)
  #     model: claude-sonnet-5-5
  #
  # The older keys (engine, llm, model, provider, api_key, decision, claude, codex) are still read.
  class AISettings
    class Error < StandardError; end

    CLI_REPORTERS = %w[claude_code codex].freeze
    DEFAULT_REPORTER = { 'provider' => 'gemini', 'model' => AIAnalysisEngine::LLMClient::DEFAULT_MODEL }.freeze
    # Classifier providers whose model can be omitted
    DEFAULT_CLASSIFIER_MODELS = { 'typesafe' => 'jev-1.13.0', 'openai' => 'gpt-6-luna' }.freeze
    # RubyLLM protocols that answer judgment questions
    JUDGE_PROTOCOLS = %i[system_one decisions].freeze
    DEFAULT_THRESHOLD = 0.3
    DEFAULT_CLASSIFIER_CONCURRENCY = 8
    DEFAULT_API_REPORTER_CONCURRENCY = 8
    # Subscription CLIs have tighter rate limits than APIs
    DEFAULT_CLI_REPORTER_CONCURRENCY = 3

    LEGACY_ENGINES = { 'jev' => 'typesafe', 'openai' => 'openai' }.freeze
    LEGACY_NO_CLASSIFIER = %w[llm gemini].freeze
    LEGACY_LLMS = { 'claude' => 'claude_code', 'codex' => 'codex' }.freeze

    # The classifier settings, or nil when the reporter checks everything itself
    attr_reader :classifier
    attr_reader :reporter

    # overrides: classifier:, classifier_model:, reporter:, reporter_model: (from the command line)
    def initialize(config, overrides = {})
      @config = config
      @overrides = overrides.compact.transform_values(&:to_s)
      @classifier = resolve_classifier
      @reporter = resolve_reporter
    end

    def classifier?
      !@classifier.nil?
    end

    def cli_reporter?
      CLI_REPORTERS.include?(@reporter['provider'])
    end

    def threshold
      @classifier.fetch('threshold', DEFAULT_THRESHOLD)
    end

    def classifier_concurrency
      @classifier.fetch('concurrency', DEFAULT_CLASSIFIER_CONCURRENCY)
    end

    def reporter_concurrency
      @reporter.fetch('concurrency', cli_reporter? ? DEFAULT_CLI_REPORTER_CONCURRENCY : DEFAULT_API_REPORTER_CONCURRENCY)
    end

    def reporter_model
      @reporter['model']
    end

    def build_classifier_client
      return nil unless classifier?

      AIAnalysisEngine::JudgeClient.new(ruby_llm_context, provider: @classifier['provider'].to_sym,
                                                          model: @classifier['model'])
    end

    def build_reporter_client
      case @reporter['provider']
      when 'claude_code' then AIAnalysisEngine::CLIClients::ClaudeCodeClient.new(command: @reporter['command'])
      when 'codex' then AIAnalysisEngine::CLIClients::CodexClient.new(command: @reporter['command'])
      else AIAnalysisEngine::LLMClient.new(ruby_llm_context, provider: @reporter['provider']&.to_sym)
      end
    end

    # One line for the console, e.g. "classifier: typesafe/jev-1.13.0, reporter: gemini/gemini-3.8-flash"
    def describe
      reporter = [@reporter['provider'], @reporter['model']].compact.join('/')
      return "reporter: #{reporter}" unless classifier?

      "classifier: #{@classifier['provider']}/#{@classifier['model']}, reporter: #{reporter}"
    end

    private

    def get(key)
      @config.get(key, nil)
    end

    def resolve_classifier
      settings = apply_override(configured_classifier, @overrides[:classifier], @overrides[:classifier_model])
      return nil if settings.nil? || settings['provider'] == 'none'

      provider = settings.fetch('provider') { raise Error, 'classifier.provider is required' }
      validate_classifier_provider!(provider)
      settings['model'] ||= DEFAULT_CLASSIFIER_MODELS.fetch(provider) do
        raise Error, "classifier.model is required for provider #{provider}"
      end
      settings
    end

    def resolve_reporter
      settings = apply_override(configured_reporter, @overrides[:reporter], @overrides[:reporter_model])
      settings = DEFAULT_REPORTER.merge(settings || {}) if settings.nil? || (settings['provider'].nil? && settings['model'].nil?)
      provider = settings['provider']
      return settings if provider.nil? || CLI_REPORTERS.include?(provider)

      raise Error, "Unknown reporter provider: #{provider}" unless RubyLLM::Provider.resolve(provider)

      settings['model'] ||= DEFAULT_REPORTER['model'] if provider == DEFAULT_REPORTER['provider']
      raise Error, "reporter.model is required for provider #{provider}" unless settings['model']

      settings
    end

    # A provider given on the command line replaces the configured one; the configured model only
    # carries over when the provider stays the same.
    def apply_override(settings, provider, model)
      if provider
        settings = settings&.fetch('provider', nil) == provider ? settings : {}
        settings = settings.merge('provider' => provider)
      end
      settings = (settings || {}).merge('model' => model) if model
      settings
    end

    def configured_classifier
      return stringify(get('classifier')) if get('classifier')

      engine = get('engine')&.to_s
      return nil if engine.nil? || LEGACY_NO_CLASSIFIER.include?(engine)

      provider = LEGACY_ENGINES.fetch(engine) { raise Error, "Unknown engine: #{engine}" }
      decision = stringify(get('decision') || {})
      engine_settings = stringify(decision[engine] || {})
      { 'provider' => provider, 'threshold' => decision['threshold'], 'concurrency' => decision['concurrency'] }
        .merge(engine_settings.slice('model', 'base_url', 'api_key')).compact
    end

    def configured_reporter
      return stringify(get('reporter')) if get('reporter')

      llm = get('llm')&.to_s
      report_concurrency = stringify(get('decision') || {})['report_concurrency']
      settings = if LEGACY_LLMS.key?(llm)
                   { 'provider' => LEGACY_LLMS[llm] }.merge(stringify(get(llm) || {}).slice('model', 'command'))
                 else
                   { 'provider' => get('provider')&.to_s, 'model' => get('model') }
                 end
      settings.merge('concurrency' => report_concurrency).compact.then { |s| s.empty? ? nil : s }
    end

    def validate_classifier_provider!(provider)
      provider_class = RubyLLM::Provider.resolve(provider)
      raise Error, "Unknown classifier provider: #{provider}" unless provider_class
      return if provider_class.protocols.keys.intersect?(JUDGE_PROTOCOLS)

      raise Error, "Provider #{provider} cannot be used as a classifier"
    end

    # Each role's api_key / base_url go to RubyLLM's <provider>_api_key / <provider>_api_base.
    # The old top-level api_key is a Gemini key.
    def ruby_llm_context
      @ruby_llm_context ||= begin
        overrides = { gemini_api_key: get('api_key') }
        [@classifier, @reporter].compact.each do |settings|
          next unless settings['provider'] && !CLI_REPORTERS.include?(settings['provider'])

          overrides[:"#{settings['provider']}_api_key"] = settings['api_key'] if settings['api_key']
          overrides[:"#{settings['provider']}_api_base"] = settings['base_url'] if settings['base_url']
        end
        AIAnalysisEngine::RubyLLMContext.build(overrides)
      end
    end

    def stringify(hash)
      hash.to_h.transform_keys(&:to_s)
    end
  end
end
