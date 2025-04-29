# frozen_string_literal: true

require 'spec_helper'
require 'omamori/static_analysers/bundler_audit_runner'

RSpec.describe Omamori::StaticAnalysers::BundlerAuditRunner do
  let(:runner) { Omamori::StaticAnalysers::BundlerAuditRunner.new }
  let(:options) { { quiet: true } }
  let(:runner_with_options) { Omamori::StaticAnalysers::BundlerAuditRunner.new(options) }
  let(:valid_json_output) do
    '{
      "version": "0.9.0",
      "created_at": "2023-09-15T12:34:56Z",
      "results": [
        {
          "type": "insecure_source",
          "source": "git://github.com/example/repo.git"
        },
        {
          "type": "unpatched_gem",
          "gem": {
            "name": "actionpack",
            "version": "3.2.10"
          },
          "advisory": {
            "id": "CVE-2013-0156",
            "path": "/path/to/advisory/file.yml",
            "url": "https://nvd.nist.gov/...",
            "title": "XML Parsing Vulnerability",
            "date": "2013-01-08",
            "description": "脆弱性の詳細説明...",
            "cvss_v2": 7.5,
            "cve": "2013-0156",
            "osvdb": null,
            "ghsa": null,
            "criticality": "high",
            "unaffected_versions": [],
            "patched_versions": ["~> 3.2.11", ">= 3.1.0"]
          }
        }
      ]
    }'
  end
  let(:invalid_json_output) { 'This is not JSON output' }

  # Mock the backtick command execution
  before do
    allow_any_instance_of(Omamori::StaticAnalysers::BundlerAuditRunner).to receive(:`).and_return("") # Default mock
  end

 describe "#run" do
   let(:parsed_valid_json_output) { JSON.parse(valid_json_output) }

   it "constructs the correct bundler-audit command" do
     expected_command = "bundle audit --format json 2>&1"
     expect(runner).to receive(:`).with(expected_command).and_return(valid_json_output)
     runner.run
   end

   it "includes options passed during initialization in the command" do
     expected_command = "bundle audit --format json --quiet 2>&1"
     expect(runner_with_options).to receive(:`).with(expected_command).and_return(valid_json_output)
     runner_with_options.run
   end

   context "when bundler-audit command executes successfully with valid JSON output" do
     it "parses the JSON output and returns the result" do
       expect(runner).to receive(:`).and_return(valid_json_output)
       # Expect JSON.parse to be called once within the run method and return the parsed output
       expect(JSON).to receive(:parse).once.with(valid_json_output).and_return(parsed_valid_json_output)

       result = runner.run
       # Expect the result to be the 'results' array from the parsed JSON
       expect(result).to eq(parsed_valid_json_output)
     end
   end

   context "when bundle command is not found" do
     it "prints an error message and returns nil" do
       expect(runner).to receive(:`).and_raise(Errno::ENOENT)
       expect_any_instance_of(Object).to receive(:puts).with("Error: bundle command not found. Is Bundler installed?")

       result = runner.run
       expect(result).to be_nil
     end
   end

   context "when bundler-audit output is not valid JSON" do
     it "prints an error message with raw output and returns nil" do
       expect(runner).to receive(:`).and_return(invalid_json_output)
       # Expect JSON.parse to be called and raise an error
       expect(JSON).to receive(:parse).with(invalid_json_output).and_raise(JSON::ParserError)
       expect_any_instance_of(Object).to receive(:puts).with("Error: Failed to parse Bundler-Audit JSON output.")
       expect_any_instance_of(Object).to receive(:puts).with("Raw output:\n#{invalid_json_output}")

       result = runner.run
       expect(result).to be_nil
     end
   end

   context "when another error occurs during execution" do
     it "prints a generic error message and returns nil" do
       error_message = "Some unexpected error during audit"
       expect(runner).to receive(:`).and_raise(StandardError, error_message)
       expect_any_instance_of(Object).to receive(:puts).with("An error occurred during Bundler-Audit execution: #{error_message}")

       result = runner.run
       expect(result).to be_nil
     end
   end
 end
end