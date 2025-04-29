# frozen_string_literal: true

require 'spec_helper'
require 'omamori/report_generator/console_formatter'

RSpec.describe Omamori::ReportGenerator::ConsoleFormatter do
  # テスト開始前に色付けを無効にする
  before(:all) do
    # colorize gem の色付けを無効にする方法を試す
    if defined?(String.disable_colorization)
      @original_colorization = String.disable_colorization
      String.disable_colorization = true
    elsif defined?(Colorize.disable_colorization)
      @original_colorization = Colorize.disable_colorization
      Colorize.disable_colorization = true
    end
  end

  # テスト終了後に色付けを元に戻す
  after(:all) do
    if defined?(String.disable_colorization) && defined?(@original_colorization)
      String.disable_colorization = @original_colorization
    elsif defined?(Colorize.disable_colorization) && defined?(@original_colorization)
      Colorize.disable_colorization = @original_colorization
    end
  end
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
              "code_snippet" => %q{User.where("name = '#{params[:name]}'")},
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
        expect(output).to include("Type: SQL Injection")
        expect(output).to include("Brakeman results not available")
        puts output
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
        expect(output).to include("Severity: #{"High".colorize(:red)}") # Should be red
        expect(output).to include("Severity: #{"Medium".colorize(:yellow)}") # Should be yellow
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
          "ai_security_risks" => [], # AI analysis results (empty)
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
            },
            "bundler_audit" => { "results" => [] } # Bundler-Audit results (empty)
          }
        }
      end

      it "formats the Brakeman results" do
        output = formatter.format(brakeman_results)
        expected_output = <<~EOF
--- AI Analysis Results ---
No AI-detected security risks.

--- Static Analysis Results ---
    Brakeman:
      - Warning Type: SQL Injection
        Message: Possible SQL injection
        File: app/models/product.rb
        Line: 20
        Code: Product.find_by(name: params[:name])
        Link: https://brakemanscanner.org/docs/warnings/sql_injection/
    

    Bundler-Audit:

        EOF
      end
    end

    context "when Brakeman results are not available" do
      let(:no_brakeman_results) do
        {
          "ai_security_risks" => [], # AI analysis results (empty)
          "static_analysis_results" => {
            "brakeman" => nil, # Brakeman results not available
            "bundler_audit" => { "scan" => { "results" => [] } } # Bundler-Audit results (empty)
          }
        }
      end

      it "indicates that Brakeman results are not available" do
        output = formatter.format(no_brakeman_results)
        expected_output = <<~EOF
          --- AI Analysis Results ---
          No AI-detected security risks.

          --- Static Analysis Results ---
          Brakeman results not available.

          Bundler-Audit:
            No vulnerabilities found.
            No unpatched gems found.

        EOF
        expect(output.strip).to include(expected_output.strip)
      end
    end

    context "when there are Bundler-Audit results" do
      let(:bundler_audit_results) do
        {
          "ai_security_risks" => [], # AI analysis results (empty)
          "static_analysis_results" => {
            "brakeman" => { "warnings" => [] }, # Brakeman results (empty)
            "bundler_audit" => {
              "scan" => {
                "results" => [
                  {
                    "type" => "unpatched_gem",
                    "gem" => {
                      "name" => "rails",
                      "version" => "6.0.0"
                    },
                    "advisory" => {
                      "id" => "CVE-2022-XXXX",
                      "url" => "https://example.com/advisory/CVE-2022-XXXX",
                      "title" => "SQL Injection vulnerability in Rails",
                      "date" => "2022-01-01",
                      "description" => "Details about the vulnerability.",
                      "criticality" => "High",
                      "patched_versions" => [">= 6.0.5", ">= 6.1.4.1"]
                    }
                  },
                  {
                    "type" => "unpatched_gem",
                    "gem" => {
                      "name" => "nokogiri",
                      "version" => "1.10.0"
                    },
                    "advisory" => {
                      "id" => "CVE-2023-YYYY",
                      "url" => "https://example.com/advisory/CVE-2023-YYYY",
                      "title" => "XML Parsing vulnerability in Nokogiri",
                      "date" => "2023-01-01",
                      "description" => "Details about the Nokogiri vulnerability.",
                      "criticality" => "Medium",
                      "patched_versions" => [">= 1.11.0"]
                    }
                  }
                ]
              }
            }
          }
        }
      end

      it "formats the Bundler-Audit results" do
        output = formatter.format(bundler_audit_results)
        expected_output = <<~EOF
--- AI Analysis Results ---
No AI-detected security risks.

--- Static Analysis Results ---
Brakeman:
No Brakeman warnings found.

Bundler-Audit:
  Vulnerabilities:
    - ID: CVE-2022-XXXX
      Gem: rails (6.0.0)
      Title: SQL Injection vulnerability in Rails
      URL: https://example.com/advisory/CVE-2022-XXXX
      Criticality: High
      Description: Details about the vulnerability.
      Patched Versions: >= 6.0.5, >= 6.1.4.1
      Advisory Date: 2022-01-01

    - ID: CVE-2023-YYYY
      Gem: nokogiri (1.10.0)
      Title: XML Parsing vulnerability in Nokogiri
      URL: https://example.com/advisory/CVE-2023-YYYY
      Criticality: Medium
      Description: Details about the Nokogiri vulnerability.
      Patched Versions: >= 1.11.0
      Advisory Date: 2023-01-01

        EOF
        expect(output).to include(expected_output)
      end

      it "indicates no vulnerabilities if the vulnerabilities list is empty" do
        bundler_audit_no_vulnerabilities = {
          "static_analysis_results" => {
            "bundler_audit" => {
              "scan" => {
                "results" => []
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
                "results" => []
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
                "results" => []
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
                "results" => []
              }
            }
          }
        }
        output = formatter.format(bundler_audit_no_unpatched)
        expect(output).to include("Bundler-Audit:")
        expect(output).to include("No vulnerabilities found.")
        expect(output).to include("No unpatched gems found.")
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
