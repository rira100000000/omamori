# frozen_string_literal: true

require 'yaml'

module Omamori
  class Config
    DEFAULT_CONFIG_PATH = ".omamorirc"

    def initialize(config_path = DEFAULT_CONFIG_PATH)
      @config_path = config_path
      @config = load_config
    end

    def get(key, default = nil)
      @config.fetch(key.to_s, default)
    end

    private

    def load_config
      if File.exist?(@config_path)
        begin
          YAML.load_file(@config_path) || {}
        rescue Psych::SyntaxError => e
          puts "Error parsing config file #{@config_path}: #{e.message}"
          {}
        end
      else
        {} # Return empty hash if config file does not exist
      end
    end
  end
end