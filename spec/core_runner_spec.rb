# frozen_string_literal: true

require 'spec_helper'
require 'omamori/core_runner'
require 'omamori/config' # Include Config for testing initialization

RSpec.describe Omamori::CoreRunner do
  let(:config_double) { instance_double(Omamori::Config) }
  let(:gemini_client_double) { instance_double(Omamori::AIAnalysisEngine::GeminiClient) }
  let(:prompt_manager_double) { instance_double(Omamori::AIAnalysisEngine::PromptManager) }
  let(:diff_splitter_double) { instance_double(Omamori::AIAnalysisEngine::DiffSplitter) }
  let(:console_formatter_double) { instance_double(Omamori::ReportGenerator::ConsoleFormatter) }
  let(:html_formatter_double) { instance_double(Omamori::ReportGenerator::HTMLFormatter) }
  let(:json_formatter_double) { instance_double(Omamori::ReportGenerator::JSONFormatter) }
  let(:brakeman_runner_double) { instance_double(Omamori::StaticAnalysers::BrakemanRunner) }
  let(:bundler_audit_runner_double) { instance_double(Omamori::StaticAnalysers::BundlerAuditRunner) }

  before do
    # Mock Config and its methods
    allow(Omamori::Config).to receive(:new).and_return(config_double)
    allow(config_double).to receive(:get).with("api_key", any_args).and_return("dummy_api_key")
    allow(config_double).to receive(:get).with("model", any_args).and_return("gemini-1.5-pro-latest")
    allow(config_double).to receive(:get).with("prompt_templates", any_args).and_return({})
    allow(config_double).to receive(:get).with("chunk_size", any_args).and_return(7000)
    allow(config_double).to receive(:get).with("report", any_args).and_return({})
    allow(config_double).to receive(:get).with("static_analysers", any_args).and_return({})
    allow(config_double).to receive(:get).with("checks", any_args).and_return(Omamori::CoreRunner::DEFAULT_RISKS_TO_CHECK)
    allow(config_double).to receive(:get).with("ci_setup", any_args).and_return({})


    # Mock component initializations
    allow(Omamori::AIAnalysisEngine::GeminiClient).to receive(:new).and_return(gemini_client_double)
    allow(Omamori::AIAnalysisEngine::PromptManager).to receive(:new).and_return(prompt_manager_double)
    allow(Omamori::AIAnalysisEngine::DiffSplitter).to receive(:new).and_return(diff_splitter_double)
    allow(Omamori::ReportGenerator::ConsoleFormatter).to receive(:new).and_return(console_formatter_double)
    allow(Omamori::ReportGenerator::HTMLFormatter).to receive(:new).and_return(html_formatter_double)
    allow(Omamori::ReportGenerator::JSONFormatter).to receive(:new).and_return(json_formatter_double)
    allow(Omamori::StaticAnalysers::BrakemanRunner).to receive(:new).and_return(brakeman_runner_double)
    allow(Omamori::StaticAnalysers::BundlerAuditRunner).to receive(:new).and_return(bundler_audit_runner_double)

    # Mock component method calls
    allow(gemini_client_double).to receive(:analyze).and_return({ "security_risks" => [] })
    allow(prompt_manager_double).to receive(:build_prompt).and_return("dummy prompt")
    allow(diff_splitter_double).to receive(:process_in_chunks).and_return({ "security_risks" => [] })
    allow(console_formatter_double).to receive(:format).and_return("console report")
    allow(html_formatter_double).to receive(:format).and_return("html report")
    allow(json_formatter_double).to receive(:format).and_return("json report")
    allow(brakeman_runner_double).to receive(:run).and_return({})
    allow(bundler_audit_runner_double).to receive(:run).and_return({})

    # Mock file operations
    allow(File).to receive(:read).and_return("") # Prevent actual file reads during tests
    allow(File).to receive(:write) # Prevent actual file writes during tests
    allow(File).to receive(:exist?).and_return(false) # Assume config file doesn't exist by default
    allow(Dir).to receive(:glob).and_return([]) # Assume no ruby files by default

    # Mock git commands
    allow_any_instance_of(Omamori::CoreRunner).to receive(:`).with("git diff --staged").and_return("")
    allow_any_instance_of(Omamori::CoreRunner).to receive(:`).with("git ls-files").and_return("") # Mock for get_full_codebase if needed
  end

  describe "#run" do
    context "when no command is specified" do
      it "defaults to the scan command with --diff mode" do
        # Create runner instance
        runner = Omamori::CoreRunner.new([])

        # Mock parse_options to set expected options
        allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
          method.call(*args) # Call original parse_options
          runner.instance_variable_set(:@options, { command: :scan, scan_mode: :diff, format: :console })
        end

        # Expect scan command logic to be executed
        expect(runner).to receive(:parse_options)
        expect(runner).to receive(:get_staged_diff).and_return("dummy diff")
        expect(runner).to receive(:combine_results)
        expect(runner).to receive(:display_report)

        runner.run
      end
    end

    context "when the scan command is specified" do
      it "runs the scan logic" do
        # Create runner instance
        runner = Omamori::CoreRunner.new(["scan"])

        # Mock parse_options to set expected options
        allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
          method.call(*args) # Call original parse_options
          runner.instance_variable_set(:@options, { command: :scan, scan_mode: :diff, format: :console })
        end

        # Expect scan command logic to be executed
        expect(runner).to receive(:parse_options)
        expect(runner).to receive(:get_staged_diff).and_return("dummy diff")
        expect(runner).to receive(:combine_results)
        expect(runner).to receive(:display_report)

        runner.run
      end

      context "with --diff option" do
        it "calls get_staged_diff and analyzes the diff if diff is small" do
          runner = Omamori::CoreRunner.new(["scan", "--diff"])
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args)
            runner.instance_variable_set(:@options, { command: :scan, scan_mode: :diff, format: :console })
          end
          allow(runner).to receive(:get_staged_diff).and_return("dummy diff")
          allow(runner).to receive(:combine_results).and_return({})
          allow(runner).to receive(:display_report)

          expect(runner).to receive(:get_staged_diff)
          expect(runner).not_to receive(:get_full_codebase)
          expect(gemini_client_double).to receive(:analyze).with(anything, anything, model: anything)
          expect(diff_splitter_double).not_to receive(:process_in_chunks)

          runner.run
        end

        it "calls diff_splitter if the diff is large" do
          runner = Omamori::CoreRunner.new(["scan", "--diff"])
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args)
            runner.instance_variable_set(:@options, { command: :scan, scan_mode: :diff, format: :console })
          end
          large_diff = "a" * (Omamori::CoreRunner::SPLIT_THRESHOLD + 1)
          allow(runner).to receive(:get_staged_diff).and_return(large_diff)
          allow(runner).to receive(:combine_results).and_return({})
          allow(runner).to receive(:display_report)

          expect(runner).to receive(:get_staged_diff)
          expect(runner).not_to receive(:get_full_codebase)
          expect(gemini_client_double).not_to receive(:analyze)
          expect(diff_splitter_double).to receive(:process_in_chunks).with(large_diff, anything, anything, anything, anything, model: anything)

          runner.run
        end
      end

      context "with --all option" do
        it "calls get_full_codebase and analyzes the codebase if codebase is small" do
          runner = Omamori::CoreRunner.new(["scan", "--all"])
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args)
            runner.instance_variable_set(:@options, { command: :scan, scan_mode: :all, format: :console })
          end
          allow(runner).to receive(:get_full_codebase).and_return("dummy code")
          allow(runner).to receive(:combine_results).and_return({})
          allow(runner).to receive(:display_report)

          expect(runner).not_to receive(:get_staged_diff)
          expect(runner).to receive(:get_full_codebase)
          expect(gemini_client_double).to receive(:analyze).with(anything, anything, model: anything)
          expect(diff_splitter_double).not_to receive(:process_in_chunks)

          runner.run
        end

        it "calls diff_splitter if the codebase is large" do
          runner = Omamori::CoreRunner.new(["scan", "--all"])
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args)
            runner.instance_variable_set(:@options, { command: :scan, scan_mode: :all, format: :console })
          end
          large_codebase = "a" * (Omamori::CoreRunner::SPLIT_THRESHOLD + 1)
          allow(runner).to receive(:get_full_codebase).and_return(large_codebase)
          allow(runner).to receive(:combine_results).and_return({})
          allow(runner).to receive(:display_report)

          expect(runner).not_to receive(:get_staged_diff)
          expect(runner).to receive(:get_full_codebase)
          expect(gemini_client_double).not_to receive(:analyze)
          expect(diff_splitter_double).to receive(:process_in_chunks).with(large_codebase, anything, anything, anything, anything, model: anything)

          runner.run
        end
      end

      context "with --format option" do
        let(:results) { { "security_risks" => [{ "risk" => "SQL Injection", "severity" => "High", "message" => "Example" }] } }

        before do
          # Mock scan logic results

          context "when format is console" do
            let(:@args) { ["scan", "--format", "console"] }
            let(:@format_option) { :console }

            it "uses the console formatter and prints to stdout" do
              expect(console_formatter_double).to receive(:format).with(results).and_return("console report")
              expect(html_formatter_double).not_to receive(:format)
              expect(json_formatter_double).not_to receive(:format)
              expect { @runner.run }.to output("console report\n").to_stdout
              expect(File).not_to receive(:write)
            end
          end

          context "when format is html" do
            let(:@args) { ["scan", "--format", "html"] }
            let(:@format_option) { :html }

            it "uses the html formatter and writes to omamori_report.html" do
              expect(console_formatter_double).not_to receive(:format)
              expect(html_formatter_double).to receive(:format).with(results).and_return("html report")
              expect(json_formatter_double).not_to receive(:format)
              expect(File).to receive(:write).with("./omamori_report.html", "html report")
              expect { @runner.run }.to_not output.to_stdout
            end
          end

          context "when format is json" do
            let(:@args) { ["scan", "--format", "json"] }
            let(:@format_option) { :json }

            it "uses the json formatter and writes to omamori_report.json" do
              expect(console_formatter_double).not_to receive(:format)
              expect(html_formatter_double).not_to receive(:format)
              expect(json_formatter_double).to receive(:format).with(results).and_return("json report")
              expect(File).to receive(:write).with("./omamori_report.json", "json report")
              expect { @runner.run }.to_not output.to_stdout
            end
          end
        end
      end
    end

    context "when the ci-setup command is specified" do
      context "with --ci github_actions option" do
        it "generates GitHub Actions workflow" do
          # Create runner instance
          runner = Omamori::CoreRunner.new(["ci-setup", "--ci", "github_actions"])

          # Mock parse_options to set expected options
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args) # Call original parse_options
            runner.instance_variable_set(:@options, { command: :ci_setup, ci_service: :github_actions })
          end

          # Expect generate_github_actions_workflow to be called
          expect(runner).to receive(:generate_github_actions_workflow)
          expect(runner).not_to receive(:generate_gitlab_ci_workflow)

          runner.run
        end
      end

      context "with --ci gitlab_ci option" do
        it "generates GitLab CI workflow" do
          # Create runner instance
          runner = Omamori::CoreRunner.new(["ci-setup", "--ci", "gitlab_ci"])

          # Mock parse_options to set expected options
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args) # Call original parse_options
            runner.instance_variable_set(:@options, { command: :ci_setup, ci_service: :gitlab_ci })
          end

          # Expect generate_gitlab_ci_workflow to be called
          expect(runner).not_to receive(:generate_github_actions_workflow)
          expect(runner).to receive(:generate_gitlab_ci_workflow)

          runner.run
        end
      end
    end
  end
  context "when the init command is specified" do
    it "generates the initial config file" do
      # Create runner instance
      runner = Omamori::CoreRunner.new(["init"])

      # Mock parse_options to set expected options
      allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
        method.call(*args) # Call original parse_options
        runner.instance_variable_set(:@options, { command: :init })
      end

      # Expect generate_config_file to be called
      expect(runner).to receive(:generate_config_file)

      runner.run
    end
  end
end