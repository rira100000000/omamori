# frozen_string_literal: true

require 'json'

module Omamori
  module ReportGenerator
    class JSONFormatter
      def initialize(output_path_prefix)
        @output_path_prefix = output_path_prefix
      end

      def format(analysis_result)
        # Convert the analysis result (Ruby Hash/Array) to a JSON string
        # Use pretty_generate for readability
        JSON.pretty_generate(analysis_result)
      end
    end
  end
end