# frozen_string_literal: true

require_relative 'ai_settings'

module Omamori
  # `omamori doctor`: checks that the configured classifier and reporters can be reached, by sending each
  # one small request, and says how to fix what is missing.
  class Doctor
    REPORTER_PROBE = 'This is a connectivity check by `omamori doctor`. There is no code to review. ' \
                     'Return {"security_risks": []}.'
    CLASSIFIER_PROBE_STATE = "puts 'hello'"
    CLASSIFIER_PROBE_QUESTIONS = { ruby: 'Is this Ruby code?' }.freeze
    CLI_INSTALL = {
      'claude_code' => 'Install Claude Code (npm install -g @anthropic-ai/claude-code) and log in with `claude`',
      'codex' => 'Install the Codex CLI (npm install -g @openai/codex) and log in with `codex login`'
    }.freeze

    def initialize(settings, json_schema:)
      @settings = settings
      @json_schema = json_schema
    end

    # Returns true when every role answered
    def run
      puts "Settings: #{@settings.describe}"
      results = []
      results << check('classifier', @settings.classifier) { check_classifier } if @settings.classifier?
      results << check('reporter', @settings.reporter) { check_reporter(@settings.reporter) }
      if @settings.reporter_fallback
        results << check('reporter.fallback', @settings.reporter_fallback) { check_reporter(@settings.reporter_fallback) }
      end
      ok = results.all?
      puts ok ? 'All checks passed. Try `omamori scan --base main`.' : 'Some checks failed. Fix them and run `omamori doctor` again.'
      ok
    end

    private

    def check(role, role_settings)
      label = "#{role} (#{[role_settings['provider'], role_settings['model']].compact.join('/')})"
      puts "Checking #{label}..."
      problem = yield
      if problem
        puts "  NG: #{problem}"
        false
      else
        puts '  OK'
        true
      end
    rescue StandardError => e
      puts "  NG: #{e.class}: #{e.message}"
      hint = credential_hint(role_settings)
      puts "  #{hint}" if hint
      false
    end

    # Returns nil when it works, or what is wrong
    def check_classifier
      answers = @settings.build_classifier_client.classify(CLASSIFIER_PROBE_STATE, CLASSIFIER_PROBE_QUESTIONS)
      return nil unless answers.values.include?(nil)

      "The classifier gave no answer. #{credential_hint(@settings.classifier)}".strip
    end

    def check_reporter(role_settings)
      provider = role_settings['provider']
      if AISettings::CLI_REPORTERS.include?(provider)
        command = role_settings['command'] || (provider == 'claude_code' ? 'claude' : 'codex')
        return "'#{command}' was not found. #{CLI_INSTALL[provider]}" unless command_exists?(command)
      end

      result = @settings.build_llm_client(role_settings).analyze(REPORTER_PROBE, @json_schema, model: role_settings['model'])
      return nil if result

      "The reporter gave no usable answer (see the warning above). #{credential_hint(role_settings)}".strip
    end

    def credential_hint(role_settings)
      provider = role_settings['provider']
      return "#{CLI_INSTALL[provider]}." if CLI_INSTALL.key?(provider)

      env = AISettings.api_key_env(provider)
      return nil unless env
      return nil if role_settings['api_key'] || !ENV[env].to_s.empty?

      "#{env} is not set."
    end

    def command_exists?(command)
      return File.executable?(command) if command.include?(File::SEPARATOR)

      ENV['PATH'].to_s.split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, command)) }
    end
  end
end
