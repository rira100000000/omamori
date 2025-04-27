# frozen_string_literal: true

require 'spec_helper'
require 'omamori/static_analysers/brakeman_runner'

RSpec.describe Omamori::StaticAnalysers::BrakemanRunner do
  let(:runner) { Omamori::StaticAnalysers::BrakemanRunner.new }
  let(:options) { "--skip-checks BasicAuth" }
  let(:runner_with_options) { Omamori::StaticAnalysers::BrakemanRunner.new(options) }
  let(:valid_json_output) { '{"warnings": [{"type": "SQL Injection", "message": "..."}]}' }
  let(:parsed_json_output) { JSON.parse(valid_json_output) }
  let(:invalid_json_output) { 'This is not JSON' }

  # Mock the backtick command execution
  before do
    allow_any_instance_of(Omamori::StaticAnalysers::BrakemanRunner).to receive(:`).and_return("") # Default mock
    # Allow puts for output
    allow_any_instance_of(Object).to receive(:puts)
  end

  describe "#run" do
    it "constructs the correct brakeman command" do
      expected_command = "brakeman -f json . --force "
      expect(runner).to receive(:`).with(expected_command).and_return(valid_json_output)
      runner.run
    end

    it "includes options passed during initialization in the command" do
      expected_command = "brakeman -f json . --force #{options}"
      expect(runner_with_options).to receive(:`).with(expected_command).and_return(valid_json_output)
      runner_with_options.run
    end


    context "when brakeman command executes successfully with valid JSON output" do
      it "parses the JSON output and returns the result" do
        expect(runner).to receive(:`).and_return(valid_json_output)
        expect(JSON).to receive(:parse).with(valid_json_output).and_call_original

        result = runner.run
        expect(result).to eq(parsed_json_output)
      end
    end

    context "when brakeman command is not found" do
      it "prints an error message and returns nil" do
        expect(runner).to receive(:`).and_raise(Errno::ENOENT)

        expect {
          result = runner.run
          expect(result).to be_nil
        }.to output(/Error: Brakeman command not found. Is Brakeman installed?/).to_stdout
      end
    end

    context "when brakeman output is not valid JSON" do
      it "prints an error message with raw output and returns nil" do
        expect(runner).to receive(:`).and_return(invalid_json_output)
        allow(JSON).to receive(:parse).and_call_original # Allow parse to raise error

        expect {
          result = runner.run
          expect(result).to be_nil
        }.to output(/Error: Failed to parse Brakeman JSON output.\nRaw output:\n#{invalid_json_output}/).to_stdout
      end
    end

    context "when another error occurs during execution" do
      it "prints a generic error message and returns nil" do
        error_message = "Some unexpected error"
        expect(runner).to receive(:`).and_raise(StandardError, error_message)

        expect {
          result = runner.run
          expect(result).to be_nil
        }.to output(/An error occurred during Brakeman execution: #{error_message}/).to_stdout
      end
    end
  end
end