# frozen_string_literal: true

require 'erb'

module Omamori
  module ReportGenerator
    class HTMLFormatter
      def initialize
        # TODO: Load template file path from config
        template_path = File.join(__dir__, "report_template.erb")
        @template = ERB.new(File.read(template_path))
      end

      def format(analysis_result)
        # Prepare data for the template
        @risks = analysis_result && analysis_result["security_risks"] ? analysis_result["security_risks"] : []

        # Render the template
        @template.result(binding)
      rescue Errno::ENOENT
        "Error: HTML template file not found."
      rescue => e
        "Error generating HTML report: #{e.message}"
      end
    end
  end
end