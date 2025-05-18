# frozen_string_literal: true

require_relative 'omamori/version'
require_relative 'omamori/core_runner'
require_relative 'omamori/ai_analysis_engine/gemini_client'
require_relative 'omamori/ai_analysis_engine/prompt_manager'
require_relative 'omamori/ai_analysis_engine/diff_splitter'
require_relative 'omamori/report_generator/console_formatter'
require_relative 'omamori/report_generator/html_formatter'
require_relative 'omamori/report_generator/json_formatter'
require_relative 'omamori/static_analysers/brakeman_runner'
require_relative 'omamori/static_analysers/bundler_audit_runner'

module Omamori
  # Your code goes here...
end
