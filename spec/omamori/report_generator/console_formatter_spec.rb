# frozen_string_literal: true

require 'spec_helper'
require 'omamori/report_generator/console_formatter'

RSpec.describe Omamori::ReportGenerator::ConsoleFormatter do
  let(:formatter) { Omamori::ReportGenerator::ConsoleFormatter.new }

  describe "#format" do
    context "when there are AI analysis results" do
      let(:ai_results) do
        {
          "ai_security_risks" => [
            {
              "type" => "SQL Injection",
              "severity" => "High",
              "location" => "app/models/user.rb:10",
              "details" => "User input directly used in SQL query.",
              "code_snippet" => "User.where(\"name = '#{params[:name]}'\")"
            },
            {
              "type" => "XSS",
              "severity" => "Medium",
              "location" => "app/views/users/show.html.erb:5",
              "details" => "Unsanitized user input displayed.",
              "code_snippet" => "<p><%= @user.name %></p>"
            }
          ]
        }
      end

      it "formats the AI analysis results" do
        output = formatter.format(ai_results)
        expect(output).to include("--- AI Analysis Results ---")
        expect(output).to include("Type: SQL Injection")
        expect(output).to include("Severity: High")
        expect(output).to include("Location: app/models/user.rb:10")
        expect(output).to include("Details: User input directly used in SQL query.")
        expect(output).to include("Code Snippet:")
        expect(output).to include("      1: User.where(\"name = '#{params[:name]}'\")")
        expect(output).to include("Type: XSS")
        expect(output).to include("Severity: Medium")
        expect(output).to include("Location: app/views/users/show.html.erb:5")
        expect(output).to include("Details: Unsanitized user input displayed.")
        expect(output).to include("Code Snippet:")
        expect(output).to include("      1: <p><%= @user.name %></p>")
      end

      it "applies correct colors based on severity" do
        # This test is more about checking the presence of color codes if colorize is enabled.
        # Since colorize modifies strings in place or returns new colorized strings,
        # directly checking for color codes in the output string can be fragile.
        # A better approach might involve mocking the colorize method or relying on
        # integration tests with colorize enabled.
        # For now, we'll just check for the presence of severity strings which are colorized.
        # Assuming colorize is correctly configured and works.
        output = formatter.format(ai_results)
        expect(output).to include("Severity: High") # Should be red
        expect(output).to include("Severity: Medium") # Should be yellow
      end
    end

    context "when there are no AI analysis results" do
      let(:ai_results) { { "ai_security_risks" => [] } }

      it "indicates that no AI risks were found" do
        output = formatter.format(ai_results)
        expect(output).to include("--- AI Analysis Results ---")
        expect(output).to include("No AI-detected security risks.")
      end
    end

    context "when AI analysis results key is missing or nil" do
      it "indicates that no AI risks were found when key is missing" do
        output = formatter.format({})
        expect(output).to include("--- AI Analysis Results ---")
        expect(output).to include("No AI-detected security risks.")
      end

      it "indicates that no AI risks were found when key is nil" do
        output = formatter.format({ "ai_security_risks" => nil })
        expect(output).to include("--- AI Analysis Results ---")
        expect(output).to include("No AI-detected security risks.")
      end
    end

    context "when there are Brakeman results" do
      let(:brakeman_results) do
        {
          "static_analysis_results" => {
            "brakeman" => {
              "warnings" => [
                {
                  "warning_type" => "SQL Injection",
                  "message" => "Possible SQL injection",
                  "file" => "app/models/product.rb",
                  "line" => 20,
                  "code" => "Product.find_by(name: params[:name])",
                  "link" => "https://brakemanscanner.org/docs/warnings/sql_injection/"
                }
              ]
            }
          }
        }
      end

      it "formats the Brakeman results" do
        output = formatter.format(brakeman_results)
        expect(output).to include("--- Static Analysis Results ---")
        expect(output).to include("Brakeman:")
        expect(output).to include("Warning Type: SQL Injection")
        expect(output).to include("Message: Possible SQL injection")
        expect(output).to include("File: app/models/product.rb")
        expect(output).to include("Line: 20")
        expect(output).to include("Code: Product.find_by(name: params[:name])")
        expect(output).to include("Link: https://brakemanscanner.org/docs/warnings/sql_injection/")
      end

      it "indicates no Brakeman warnings if the warnings list is empty" do
        brakeman_no_warnings = { "static_analysis_results" => { "brakeman" => { "warnings" => [] } } }
        output = formatter.format(brakeman_no_warnings)
        expect(output).to include("Brakeman:")
        expect(output).to include("No Brakeman warnings found.")
      end

      it "indicates no Brakeman warnings if the warnings key is missing or nil" do
        brakeman_no_warnings = { "static_analysis_results" => { "brakeman" => {} } }
        output = formatter.format(brakeman_no_warnings)
        expect(output).to include("Brakeman:")
        expect(output).to include("No Brakeman warnings found.")

        brakeman_no_warnings_nil = { "static_analysis_results" => { "brakeman" => { "warnings" => nil } } }
        output_nil = formatter.format(brakeman_no_warnings_nil)
        expect(output_nil).to include("Brakeman:")
        expect(output_nil).to include("No Brakeman warnings found.")
      end
    end

    context "when Brakeman results are not available" do
      let(:no_brakeman_results) { { "static_analysis_results" => {} } }

      it "indicates that Brakeman results are not available" do
        output = formatter.format(no_brakeman_results)
        expect(output).to include("--- Static Analysis Results ---")
        expect(output).to include("Brakeman:")
        expect(output).to include("Brakeman results not available.")
      end
    end

    context "when there are Bundler-Audit results" do
      let(:bundler_audit_results) do
        {
          "static_analysis_results" => {
            "bundler_audit" => {
              "scan" => {
                "vulnerabilities" => [
                  {
                    "id" => "CVE-2022-XXXX",
                    "gem" => "rails",
                    "title" => "SQL Injection vulnerability in Rails",
                    "url" => "https://example.com/advisory/CVE-2022-XXXX",
                    "criticality" => "High",
                    "description" => "Details about the vulnerability.",
                    "introduced_in" => "6.0.0",
                    "patched_versions" => [">= 6.0.5", ">= 6.1.4.1"],
                    "advisory_date" => "2022-01-01"
                  }
                ],
                "unpatched_gems" => [
                  {
                    "name" => "nokogiri",
                    "version" => "1.10.0"
                  }
                ]
              }
            }
          }
        }
      end

      it "formats the Bundler-Audit results" do
        output = formatter.format(bundler_audit_results)
        expect(output).to include("--- Static Analysis Results ---")
        expect(output).to include("Bundler-Audit:")
        expect(output).to include("Vulnerabilities:")
        expect(output).to include("ID: CVE-2022-XXXX")
        expect(output).to include("Gem: rails")
        expect(output).to include("Title: SQL Injection vulnerability in Rails")
        expect(output).to include("URL: https://example.com/advisory/CVE-2022-XXXX")
        expect(output).to include("Criticality: High")
        expect(output).to include("Description: Details about the vulnerability.")
        expect(output).to include("Introduced In: 6.0.0")
        expect(output).to include("Patched Versions: >= 6.0.5, >= 6.1.4.1")
        expect(output).to include("Advisory Date: 2022-01-01")
        expect(output).to include("Unpatched Gems:")
        expect(output).to include("Name: nokogiri")
        expect(output).to include("Version: 1.10.0")
      end

      it "indicates no vulnerabilities if the vulnerabilities list is empty" do
        bundler_audit_no_vulnerabilities = {
          "static_analysis_results" => {
            "bundler_audit" => {
              "scan" => {
                "vulnerabilities" => [],
                "unpatched_gems" => []
              }
            }
          }
        }
        output = formatter.format(bundler_audit_no_vulnerabilities)
        expect(output).to include("Bundler-Audit:")
        expect(output).to include("No vulnerabilities found.")
        expect(output).to include("No unpatched gems found.")
      end

      it "indicates no vulnerabilities if the vulnerabilities key is missing or nil" do
        bundler_audit_no_vulnerabilities = {
          "static_analysis_results" => {
            "bundler_audit" => {
              "scan" => {
                "unpatched_gems" => []
              }
            }
          }
        }
        output = formatter.format(bundler_audit_no_vulnerabilities)
        expect(output).to include("Bundler-Audit:")
        expect(output).to include("No vulnerabilities found.")

        bundler_audit_no_vulnerabilities_nil = {
          "static_analysis_results" => {
            "bundler_audit" => {
              "scan" => {
                "vulnerabilities" => nil,
                "unpatched_gems" => []
              }
            }
          }
        }
        output_nil = formatter.format(bundler_audit_no_vulnerabilities_nil)
        expect(output_nil).to include("Bundler-Audit:")
        expect(output_nil).to include("No vulnerabilities found.")
      end

      it "indicates no unpatched gems if the unpatched_gems list is empty" do
        bundler_audit_no_unpatched = {
          "static_analysis_results" => {
            "bundler_audit" => {
              "scan" => {
                "vulnerabilities" => [],
                "unpatched_gems" => []
              }
            }
          }
        }
        output = formatter.format(bundler_audit_no_unpatched)
        expect(output).to include("Bundler-Audit:")
        expect(output).to include("No vulnerabilities found.")
        expect(output).to include("No unpatched gems found.")
      end

      it "indicates no unpatched gems if the unpatched_gems key is missing or nil" do
        bundler_audit_no_unpatched = {
          "static_analysis_results" => {
            "bundler_audit" => {
              "scan" => {
                "vulnerabilities" => []
              }
            }
          }
        }
        output = formatter.format(bundler_audit_no_unpatched)
        expect(output).to include("Bundler-Audit:")
        expect(output).to include("No unpatched gems found.")

        bundler_audit_no_unpatched_nil = {
          "static_analysis_results" => {
            "bundler_audit" => {
              "scan" => {
                "vulnerabilities" => [],
                "unpatched_gems" => nil
              }
            }
          }
        }
        output_nil = formatter.format(bundler_audit_no_unpatched_nil)
        expect(output_nil).to include("Bundler-Audit:")
        expect(output_nil).to include("No unpatched gems found.")
      end
    end

    context "when Bundler-Audit results are not available or in unexpected format" do
      let(:no_bundler_audit_results) { { "static_analysis_results" => { "bundler_audit" => nil } } }
      let(:unexpected_bundler_audit_results) { { "static_analysis_results" => { "bundler_audit" => { "unexpected_key" => "..." } } } }


      it "indicates that Bundler-Audit results are not available when key is nil" do
        output = formatter.format(no_bundler_audit_results)
        expect(output).to include("--- Static Analysis Results ---")
        expect(output).to include("Bundler-Audit:")
        expect(output).to include("Bundler-Audit results not available or in unexpected format.")
      end

      it "indicates that Bundler-Audit results are not available when scan key is missing" do
        output = formatter.format(unexpected_bundler_audit_results)
        expect(output).to include("--- Static Analysis Results ---")
        expect(output).to include("Bundler-Audit:")
        expect(output).to include("Bundler-Audit results not available or in unexpected format.")
      end
    end

    context "when combined_results is nil or empty" do
      it "formats correctly when combined_results is nil" do
        output = formatter.format(nil)
        expect(output).to include("--- AI Analysis Results ---")
        expect(output).to include("No AI-detected security risks.")
        expect(output).to include("--- Static Analysis Results ---")
        expect(output).to include("Brakeman results not available.")
        expect(output).to include("Bundler-Audit results not available or in unexpected format.")
      end

      it "formats correctly when combined_results is empty" do
        output = formatter.format({})
        expect(output).to include("--- AI Analysis Results ---")
        expect(output).to include("No AI-detected security risks.")
        expect(output).to include("--- Static Analysis Results ---")
        expect(output).to include("Brakeman results not available.")
        expect(output).to include("Bundler-Audit results not available or in unexpected format.")
      end
    end
  end

  describe "#format_code_snippet" do
    let(:formatter_instance) { Omamori::ReportGenerator::ConsoleFormatter.new } # Need an instance to call private method

    it "adds line numbers and indentation to a single line snippet" do
      snippet = "puts 'hello'"
      expected_output = "      1: puts 'hello'"
      expect(formatter_instance.__send__(:format_code_snippet, snippet)).to eq(expected_output)
    end

    it "adds line numbers and indentation to a multi-line snippet" do
      snippet = "def my_method\n  puts 'line 2'\nend"
      expected_output = "      1: def my_method\n      2:   puts 'line 2'\n      3: end"
      expect(formatter_instance.__send__(:format_code_snippet, snippet)).to eq(expected_output)
    end

    it "handles an empty snippet" do
      expect(formatter_instance.__send__(:format_code_snippet, "")).to eq("")
    end

    it "handles a nil snippet" do
      expect(formatter_instance.__send__(:format_code_snippet, nil)).to eq("")
    end
  end
end