# frozen_string_literal: true

require 'optparse'

module Omamori
  class CoreRunner
    def initialize(args)
      @args = args
      @options = {}
    end

    def run
      parse_options

      case @options[:scan_mode]
      when :diff
        diff_content = get_staged_diff
        puts "Staged Diff Content:\n#{diff_content}" # TODO: Pass diff to AI analysis
      when :all
        puts "Full code scan not yet implemented." # TODO: Implement full code scan
      end

      puts "Running omamori with options: #{@options}"
    end

    private

    def parse_options
      OptionParser.new do |opts|
        opts.banner = "Usage: omamori scan [options]"

        opts.on("--diff", "Scan only the staged differences (default)") do
          @options[:scan_mode] = :diff
        end

        opts.on("--all", "Scan the entire codebase") do
          @options[:scan_mode] = :all
        end

        opts.on("-h", "--help", "Prints this help") do
          puts opts
          exit
        end
      end.parse!(@args)

      @options[:scan_mode] ||= :diff # Default to diff scan
    end

    def get_staged_diff
      `git diff --staged`
    end
  end
end