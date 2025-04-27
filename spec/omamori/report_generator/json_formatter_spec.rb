# frozen_string_literal: true

require 'spec_helper'
require 'omamori/report_generator/json_formatter'

RSpec.describe Omamori::ReportGenerator::JSONFormatter do
  let(:formatter) { Omamori::ReportGenerator::JSONFormatter.new("./reports") } # output_path_prefix is not used in format

  describe "#format" do
    it "converts a hash to a pretty JSON string" do
      analysis_result = {
        "ai_security_risks" => [
          { "type" => "XSS", "severity" => "High" }
        ],
        "static_analysis_results" => {
          "brakeman" => { "warnings" => [] }
        }
      }
      expected_json = JSON.pretty_generate(analysis_result)

      expect(formatter.format(analysis_result)).to eq(expected_json)
    end

    it "returns a valid JSON string" do
      analysis_result = { "key" => "value", "number" => 123 }
      json_string = formatter.format(analysis_result)
      expect { JSON.parse(json_string) }.not_to raise_error
    end

    it "uses JSON.pretty_generate for formatted output" do
      analysis_result = { "a" => 1, "b" => 2 }
      # Check if pretty_generate is called with the correct argument
      expect(JSON).to receive(:pretty_generate).with(analysis_result).and_call_original
      formatter.format(analysis_result)
    end

    it "handles nil input" do
      expect(formatter.format(nil)).to eq("null")
    end

    it "handles an empty hash input" do
      expect(formatter.format({})).to eq("{}")
    end

    it "handles an array input" do
      analysis_result = [1, 2, 3]
      expected_json = JSON.pretty_generate(analysis_result)
      expect(formatter.format(analysis_result)).to eq(expected_json)
    end
  end
end