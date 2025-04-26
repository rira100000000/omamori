# frozen_string_literal: true

require 'colorize'

module Omamori
  module ReportGenerator
    class ConsoleFormatter
      SEVERITY_COLORS = {
        "Critical" => :red,
        "High" => :red,
        "Medium" => :yellow,
        "Low" => :blue,
        "Info" => :green,
      }.freeze

      def format(analysis_result)
        output = ""
        if analysis_result && analysis_result["security_risks"] && !analysis_result["security_risks"].empty?
          output += "Detected Security Risks:\n".colorize(:bold)
          analysis_result["security_risks"].each do |risk|
            severity_color = SEVERITY_COLORS[risk["severity"]] || :white
            output += "  - Type: #{risk["type"].colorize(severity_color)}\n"
            output += "    Severity: #{risk["severity"].colorize(severity_color)}\n"
            output += "    Location: #{risk["location"]}\n"
            output += "    Details: #{risk["details"]}\n"
            output += "    Code Snippet:\n"
            output += format_code_snippet(risk["code_snippet"])
            output += "\n"
          end
        else
          output += "No security risks detected.\n".colorize(:green)
        end
        output
      end

      private

      def format_code_snippet(snippet)
        # Add line numbers and indent the snippet
        snippet.to_s.each_line.with_index(1).map { |line, i| "      #{i}: #{line}" }.join
      end
    end
  end
end