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

      def format(combined_results)
        output = ""

        # Format AI Analysis Results
        ai_risks = combined_results && combined_results["ai_security_risks"] ? combined_results["ai_security_risks"] : []
        if !ai_risks.empty?
          output += "--- AI Analysis Results ---\n".colorize(:bold)
          ai_risks.each do |risk|
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
          output += "--- AI Analysis Results ---\n".colorize(:bold)
          output += "No AI-detected security risks.\n".colorize(:green)
        end
        output += "\n"

        # Format Static Analysis Results
        static_results = combined_results && combined_results["static_analysis_results"] ? combined_results["static_analysis_results"] : {}
        output += "--- Static Analysis Results ---\n".colorize(:bold)

        # Format Brakeman Results
        brakeman_result = static_results["brakeman"]
        if brakeman_result
          output += "Brakeman:\n".colorize(:underline)
          if brakeman_result["warnings"] && !brakeman_result["warnings"].empty?
            brakeman_result["warnings"].each do |warning|
              severity_color = SEVERITY_COLORS[warning["confidence"]] || :white # Map Brakeman confidence to severity color
              output += "  - Warning Type: #{warning["warning_type"].colorize(severity_color)}\n"
              output += "    Message: #{warning["message"]}\n"
              output += "    File: #{warning["file"]}\n"
              output += "    Line: #{warning["line"]}\n"
              output += "    Code: #{warning["code"]}\n"
              output += "    Link: #{warning["link"]}\n"
              output += "\n"
            end
          else
            output += "No Brakeman warnings found.\n".colorize(:green)
          end
        else
          output += "Brakeman results not available.\n".colorize(:yellow)
        end
        output += "\n"

        # Format Bundler-Audit Results
        bundler_audit_result = static_results["bundler_audit"]
        if bundler_audit_result
          output += "Bundler-Audit:\n".colorize(:underline)
          # TODO: Parse and format Bundler-Audit JSON output
          output += "Bundler-Audit raw result (parsing not yet implemented):\n"
          output += JSON.pretty_generate(bundler_audit_result) + "\n"
        else
          output += "Bundler-Audit results not available.\n".colorize(:yellow)
        end
        output += "\n"

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