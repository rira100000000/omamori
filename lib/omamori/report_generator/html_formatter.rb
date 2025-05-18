# frozen_string_literal: true

require 'erb'

module Omamori
  module ReportGenerator
    class HTMLFormatter
      def initialize(output_path_prefix, template_path = nil)
        @output_path_prefix = output_path_prefix
        # Use provided template_path if not nil, otherwise use default
        @template_path = template_path || File.join(__dir__, 'report_template.erb')
        @template = ERB.new(File.read(@template_path))
      rescue Errno::ENOENT
        raise "HTML template file not found at #{@template_path}" # Raise error if template is not found
      end

      def format(combined_results)
        # Prepare data for the template
        @ai_risks = combined_results && combined_results['ai_security_risks'] ? combined_results['ai_security_risks'] : []
        @static_results = combined_results && combined_results['static_analysis_results'] ? combined_results['static_analysis_results'] : {}

        # Render the template
        @template.result(binding)
      rescue Errno::ENOENT
        'Error: HTML template file not found.'
      rescue StandardError => e
        "Error generating HTML report: #{e.message}"
      end
    end
  end
end
