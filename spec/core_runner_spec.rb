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

    # Stub ignore_patterns for the config_double
    allow(config_double).to receive(:ignore_patterns).and_return([]) # Default to empty array

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
    # Add this line to mock instance_variable_get for the diff_splitter_double
    allow(diff_splitter_double).to receive(:instance_variable_get).with(:@chunk_size).and_return(7000)

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
          large_diff = "a" * (Omamori::CoreRunner::DEFAULT_SPLIT_THRESHOLD + 1)
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
          large_codebase = "a" * (Omamori::CoreRunner::DEFAULT_SPLIT_THRESHOLD + 1)
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

      context "when scan command is specified with paths" do
        let(:runner) { Omamori::CoreRunner.new([]) } # Define runner here
        let(:ignore_patterns) { [] }
        let(:force_scan_ignored) { false }
        let(:files_to_scan) { ["/project/root/file1.rb", "/project/root/dir/file2.rb"] }
        let(:file1_content) { "def method1; end" }
        let(:file2_content) { "def method2; end" }
        let(:combined_content) { "# File: /project/root/file1.rb\n#{file1_content}\n\n# File: /project/root/dir/file2.rb\n#{file2_content}\n\n" }
        let(:analysis_result) { { "security_risks" => [] } }

        before do
          # Mock collect_files_from_paths to return predefined file list
          allow(runner).to receive(:collect_files_from_paths).and_return(files_to_scan)
          # Mock File.read for the collected files
          allow(File).to receive(:read).with("/project/root/file1.rb").and_return(file1_content)
          allow(File).to receive(:read).with("/project/root/dir/file2.rb").and_return(file2_content)
          # Mock AI analysis for individual files
          allow(gemini_client_double).to receive(:analyze).and_return(analysis_result)
          allow(diff_splitter_double).to receive(:process_in_chunks).and_return(analysis_result)
          # Mock prompt building
          allow(prompt_manager_double).to receive(:build_prompt).and_return("dummy prompt")
          # Mock combine_results and display_report
          allow(runner).to receive(:combine_results).and_return({})
          allow(runner).to receive(:display_report)
        end

        it "calls collect_files_from_paths and analyzes each file" do
          # runner = Omamori::CoreRunner.new(["scan", "file1.rb", "dir/"]) # Remove local definition
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args)
            runner.instance_variable_set(:@options, { command: :scan, scan_mode: :paths, format: :console, force_scan_ignored: force_scan_ignored })
            runner.instance_variable_set(:@target_paths, ["file1.rb", "dir/"])
          end

          expect(runner).to receive(:collect_files_from_paths).with(["file1.rb", "dir/"], anything, force_scan_ignored)
          expect(File).to receive(:read).with("/project/root/file1.rb")
          expect(File).to receive(:read).with("/project/root/dir/file2.rb")
          expect(prompt_manager_double).to receive(:build_prompt).with(file1_content, anything, anything, file_path: "/project/root/file1.rb")
          expect(prompt_manager_double).to receive(:build_prompt).with(file2_content, anything, anything, file_path: "/project/root/dir/file2.rb")
          expect(gemini_client_double).to receive(:analyze).twice # Called for each file if not split
          expect(runner).to receive(:combine_results)
          expect(runner).to receive(:display_report)

          runner.run
        end

        it "uses diff_splitter for large files" do
          large_file_content = "a" * (Omamori::CoreRunner::DEFAULT_SPLIT_THRESHOLD + 1)
          allow(File).to receive(:read).with("/project/root/large_file.rb").and_return(large_file_content)
          files_to_scan = ["/project/root/large_file.rb"]
          allow(runner).to receive(:collect_files_from_paths).and_return(files_to_scan)

          # runner = Omamori::CoreRunner.new(["scan", "large_file.rb"]) # Remove local definition
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args)
            runner.instance_variable_set(:@options, { command: :scan, scan_mode: :paths, format: :console, force_scan_ignored: force_scan_ignored })
            runner.instance_variable_set(:@target_paths, ["large_file.rb"])
          end

          expect(runner).to receive(:collect_files_from_paths).with(["large_file.rb"], anything, force_scan_ignored)
          expect(File).to receive(:read).with("/project/root/large_file.rb")
          expect(diff_splitter_double).to receive(:process_in_chunks).with(large_file_content, anything, anything, anything, anything, file_path: "/project/root/large_file.rb", model: anything)
          expect(gemini_client_double).not_to receive(:analyze) # Should use splitter instead
          expect(runner).to receive(:combine_results)
          expect(runner).to receive(:display_report)

          runner.run
        end

        it "handles no Ruby files found in specified paths" do
          allow(runner).to receive(:collect_files_from_paths).and_return([]) # No files found

          # runner = Omamori::CoreRunner.new(["scan", "non_ruby_file.txt"]) # Remove local definition
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args)
            runner.instance_variable_set(:@options, { command: :scan, scan_mode: :paths, format: :console, force_scan_ignored: force_scan_ignored })
            runner.instance_variable_set(:@target_paths, ["non_ruby_file.txt"])
          end

          expect(runner).to receive(:collect_files_from_paths).with(["non_ruby_file.txt"], anything, force_scan_ignored)
          expect(File).not_to receive(:read)
          expect(gemini_client_double).not_to receive(:analyze)
          expect(diff_splitter_double).not_to receive(:process_in_chunks)
          expect(runner).to receive(:combine_results) # Still combine results (empty)
          expect(runner).to receive(:display_report) # Still display report (empty)
          expect { runner.run }.to output(/No Ruby files found in the specified paths./).to_stdout
        end
      context "and .omamoriignore is present" do
        let(:ignore_patterns) { ["ignored_file.rb", "ignored_dir/"] }

        it "excludes files matching ignore patterns" do
          files_to_scan = ["/project/root/file1.rb", "/project/root/ignored_file.rb", "/project/root/ignored_dir/file3.rb"]
          expected_files_after_ignore = ["/project/root/file1.rb"]
          # allow(runner).to receive(:collect_files_from_paths).and_return(expected_files_after_ignore) # This line is removed/commented out

          # runner = Omamori::CoreRunner.new(["scan", "file1.rb", "ignored_file.rb", "ignored_dir/"]) # Remove local definition
          allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
            method.call(*args)
            runner.instance_variable_set(:@options, { command: :scan, scan_mode: :paths, format: :console, force_scan_ignored: false })
            runner.instance_variable_set(:@target_paths, ["file1.rb", "ignored_file.rb", "ignored_dir/"])
          end

          expect(runner).to receive(:collect_files_from_paths).with(["file1.rb", "ignored_file.rb", "ignored_dir/"], anything, false).and_return(expected_files_after_ignore)
          expect(File).to receive(:read).with("/project/root/file1.rb").and_return("def sample_method; end")
          expect(File).not_to receive(:read).with("/project/root/ignored_file.rb")
          expect(File).not_to receive(:read).with("/project/root/ignored_dir/file3.rb")
          expect(gemini_client_double).to receive(:analyze).once # Only for file1.rb
          expect(runner).to receive(:combine_results)
          expect(runner).to receive(:display_report)

          # Stub ignore_patterns for the test
          allow(config_double).to receive(:ignore_patterns).and_return(ignore_patterns)

          runner.run
        end

        context "and --force-scan-ignored is true" do
          let(:force_scan_ignored) { true }

          it "includes files matching ignore patterns" do
            files_to_scan = ["/project/root/file1.rb", "/project/root/ignored_file.rb", "/project/root/ignored_dir/file3.rb"]
            # With force_scan_ignored, all specified Ruby files should be included
            expected_files_after_ignore = ["/project/root/file1.rb", "/project/root/ignored_file.rb", "/project/root/ignored_dir/file3.rb"]
            allow(runner).to receive(:collect_files_from_paths).and_return(expected_files_after_ignore)

            # Stub ignore_patterns for this test case
            allow(@config).to receive(:ignore_patterns).and_return(ignore_patterns)

            # runner = Omamori::CoreRunner.new(["scan", "file1.rb", "ignored_file.rb", "ignored_dir/", "--force-scan-ignored"]) # Remove local definition
            allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
              method.call(*args)
              runner.instance_variable_set(:@options, { command: :scan, scan_mode: :paths, format: :console, force_scan_ignored: true })
              runner.instance_variable_set(:@target_paths, ["file1.rb", "ignored_file.rb", "ignored_dir/"])
            end
          end
        end
      end
    end # Add missing end for "when scan command is specified with paths" context

    it "runs Brakeman and includes its results" do
      files_to_scan = ["/project/root/file1.rb"]
      brakeman_results = { "warnings" => [{ "type" => "Cross Site Scripting", "file" => "/project/root/file1.rb" }] }
      
      runner = Omamori::CoreRunner.new(["scan", "file1.rb"]) # Define runner here
      allow(runner).to receive(:collect_files_from_paths).and_return(files_to_scan)
      allow(File).to receive(:read).with("/project/root/file1.rb").and_return("dummy content")
      allow(brakeman_runner_double).to receive(:run).and_return(brakeman_results)
      allow(runner).to receive(:combine_results).and_return({})
      allow(runner).to receive(:display_report)

      allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
        method.call(*args)
        runner.instance_variable_set(:@options, { command: :scan, scan_mode: :paths, format: :console, force_scan_ignored: false })
        runner.instance_variable_set(:@target_paths, ["file1.rb"])
      end

      expect(brakeman_runner_double).to receive(:run)
      runner.run
    end

    context "when the scan command is specified with --ai option" do
      it "runs only AI analysis, skipping static analysers" do
        # Create runner instance with --ai option
        runner = Omamori::CoreRunner.new(["scan", "--ai"])

        # Mock parse_options to set expected options including :only_ai
        allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
          method.call(*args) # Call original parse_options
          runner.instance_variable_set(:@options, { command: :scan, scan_mode: :diff, format: :console, only_ai: true })
        end

        # Mock necessary methods for scan logic
        allow(runner).to receive(:get_staged_diff).and_return("dummy diff")
        allow(runner).to receive(:combine_results).and_return({})
        allow(runner).to receive(:display_report)
        allow(gemini_client_double).to receive(:analyze).and_return({ "security_risks" => [] })
        allow(prompt_manager_double).to receive(:build_prompt).and_return("dummy prompt")


        # Expect static analyser run methods NOT to be called
        expect(brakeman_runner_double).not_to receive(:run)
        expect(bundler_audit_runner_double).not_to receive(:run)

        # Expect AI analysis methods to be called
        expect(runner).to receive(:get_staged_diff) # Or get_full_codebase depending on scan_mode
        expect(gemini_client_double).to receive(:analyze) # Or diff_splitter_double.process_in_chunks

        runner.run
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

  describe "#collect_files_from_paths" do
    let(:runner) { Omamori::CoreRunner.new([]) } # Create a runner instance for access to the method
    let(:ignore_patterns) { [] }
    let(:force_scan_ignored) { false }

    before do
      # Mock File and Dir operations for this describe block
      allow(File).to receive(:file?).and_call_original
      allow(File).to receive(:directory?).and_call_original
      allow(File).to receive(:extname).and_call_original
      allow(File).to receive(:expand_path).and_call_original
      allow(Dir).to receive(:glob).and_call_original
      allow(runner).to receive(:matches_ignore_pattern?).and_call_original # Allow the actual method call
    end

    context "when given a file path" do
      it "returns the file path if it's a Ruby file and not ignored" do
        allow(File).to receive(:file?).with(File.expand_path("path/to/file.rb")).and_return(true)
        allow(File).to receive(:extname).with(File.expand_path("path/to/file.rb")).and_return(".rb")
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/file.rb"), ignore_patterns, force_scan_ignored).and_return(false)
        expect(runner.send(:collect_files_from_paths, ["path/to/file.rb"], ignore_patterns, force_scan_ignored)).to eq([File.expand_path("path/to/file.rb")])
      end

      it "does not return the file path if it's not a Ruby file" do
        allow(File).to receive(:file?).with("path/to/file.txt").and_return(true)
        allow(File).to receive(:extname).with("path/to/file.txt").and_return(".txt")
        expect(runner.send(:collect_files_from_paths, ["path/to/file.txt"], ignore_patterns, force_scan_ignored)).to be_empty
      end

      it "does not return the file path if it is ignored" do
        allow(File).to receive(:file?).with("path/to/ignored.rb").and_return(true)
        allow(File).to receive(:extname).with("path/to/ignored.rb").and_return(".rb")
        allow(runner).to receive(:matches_ignore_pattern?).with("path/to/ignored.rb", ignore_patterns, force_scan_ignored).and_return(true)
        expect(runner.send(:collect_files_from_paths, ["path/to/ignored.rb"], ignore_patterns, force_scan_ignored)).to be_empty
      end

      it "returns the file path if it is ignored but force_scan_ignored is true" do
        allow(File).to receive(:file?).with(File.expand_path("path/to/ignored.rb")).and_return(true)
        allow(File).to receive(:extname).with(File.expand_path("path/to/ignored.rb")).and_return(".rb")
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/ignored.rb"), ignore_patterns, true).and_return(false) # matches_ignore_pattern? should return false when force_scan_ignored is true
        expect(runner.send(:collect_files_from_paths, ["path/to/ignored.rb"], ignore_patterns, true)).to eq([File.expand_path("path/to/ignored.rb")])
      end
    end

    context "when given a directory path" do
      it "returns all Ruby files within the directory recursively that are not ignored" do
        allow(File).to receive(:directory?).with(File.expand_path("path/to/dir")).and_return(true)
        allow(Dir).to receive(:glob).with(File.join(File.expand_path("path/to/dir"), "**", "*.rb")).and_return(["path/to/dir/file1.rb", "path/to/dir/subdir/file2.rb"].map { |f| File.expand_path(f) })
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/file1.rb"), ignore_patterns, force_scan_ignored).and_return(false)
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/subdir/file2.rb"), ignore_patterns, force_scan_ignored).and_return(false)
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/file.txt"), ignore_patterns, force_scan_ignored).and_return(false) # .txt files are filtered by glob

        expected_files = [File.expand_path("path/to/dir/file1.rb"), File.expand_path("path/to/dir/subdir/file2.rb")]
        expect(runner.send(:collect_files_from_paths, ["path/to/dir"], ignore_patterns, force_scan_ignored)).to match_array(expected_files)
      end

      it "does not return ignored files within the directory" do
        allow(File).to receive(:directory?).with(File.expand_path("path/to/dir")).and_return(true)
        allow(Dir).to receive(:glob).with(File.join(File.expand_path("path/to/dir"), "**", "*.rb")).and_return(["path/to/dir/file1.rb", "path/to/dir/ignored_file.rb"].map { |f| File.expand_path(f) })
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/file1.rb"), ignore_patterns, force_scan_ignored).and_return(false)
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/ignored_file.rb"), ignore_patterns, force_scan_ignored).and_return(true)

        expected_files = [File.expand_path("path/to/dir/file1.rb")]
        expect(runner.send(:collect_files_from_paths, ["path/to/dir"], ignore_patterns, force_scan_ignored)).to match_array(expected_files)
      end

      it "returns ignored files within the directory if force_scan_ignored is true" do
        allow(File).to receive(:directory?).with(File.expand_path("path/to/dir")).and_return(true)
        allow(Dir).to receive(:glob).with(File.join(File.expand_path("path/to/dir"), "**", "*.rb")).and_return(["path/to/dir/file1.rb", "path/to/dir/ignored_file.rb"].map { |f| File.expand_path(f) })
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/file1.rb"), ignore_patterns, true).and_return(false)
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/ignored_file.rb"), ignore_patterns, true).and_return(false) # matches_ignore_pattern? will return false internally
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/file1.rb"), ignore_patterns, false).and_return(false) # Add this line to mock the call with force_scan_ignored = false
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/ignored_file.rb"), ignore_patterns, false).and_return(true) # Add this line to mock the call with force_scan_ignored = false


        expected_files = [File.expand_path("path/to/dir/file1.rb"), File.expand_path("path/to/dir/ignored_file.rb")]
        expect(runner.send(:collect_files_from_paths, ["path/to/dir"], ignore_patterns, true)).to match_array(expected_files)
      end
    end

    context "when given multiple paths" do
      it "returns unique Ruby files from all specified paths" do
        allow(File).to receive(:file?).with(File.expand_path("file1.rb")).and_return(true)
        allow(File).to receive(:extname).with(File.expand_path("file1.rb")).and_return(".rb")
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("file1.rb"), ignore_patterns, force_scan_ignored).and_return(false)

        allow(File).to receive(:directory?).with(File.expand_path("path/to/dir")).and_return(true)
        allow(Dir).to receive(:glob).with(File.join(File.expand_path("path/to/dir"), "**", "*.rb")).and_return(["path/to/dir/file2.rb"].map { |f| File.expand_path(f) })
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/file2.rb"), ignore_patterns, force_scan_ignored).and_return(false)
        allow(runner).to receive(:matches_ignore_pattern?).with(File.expand_path("path/to/dir/file1.rb"), ignore_patterns, force_scan_ignored).and_return(false)

        expected_files = [File.expand_path("file1.rb"), File.expand_path("path/to/dir/file2.rb")]
        expect(runner.send(:collect_files_from_paths, ["file1.rb", "path/to/dir"], ignore_patterns, force_scan_ignored)).to match_array(expected_files)
      end
    end

    context "when given a non-existent path" do
      it "prints a warning and does not return any files" do
        allow(File).to receive(:file?).with("non_existent_path").and_return(false)
        allow(File).to receive(:directory?).with("non_existent_path").and_return(false)
        expect { runner.send(:collect_files_from_paths, ["non_existent_path"], ignore_patterns, force_scan_ignored) }.to output(/Warning: Path not found or is not a file\/directory: non_existent_path/).to_stdout
        expect(runner.send(:collect_files_from_paths, ["non_existent_path"], ignore_patterns, force_scan_ignored)).to be_empty
      end
    end
  end

  context "when the init command is specified" do
    it "generates the initial config file and .omamoriignore" do
      # Create runner instance
      runner = Omamori::CoreRunner.new(["init"])

      # Mock parse_options to set expected options
      allow(runner).to receive(:parse_options).and_wrap_original do |method, *args|
        method.call(*args) # Call original parse_options
        runner.instance_variable_set(:@options, { command: :init })
      end

      # Expect generate_initial_files to be called
      expect(runner).to receive(:generate_initial_files)

      runner.run
    end
  end
end

  describe "#parse_options" do
    # Remove let(:runner) and ARGV manipulation in before/after blocks
    # let(:runner) { Omamori::CoreRunner.new([]) } # Create a runner instance for access to the method
    # let(:original_argv) { ARGV.dup }
    #
    # before do
    #   ARGV.replace([]) # Reset ARGV before each test
    # end
    #
    # after do
    #   ARGV.replace(original_argv) # Restore ARGV after each test
    # end

    it "defaults to scan command with diff mode when no arguments are given" do
      runner = Omamori::CoreRunner.new([])
      runner.send(:parse_options)
      expect(runner.instance_variable_get(:@options)[:command]).to eq(:scan)
      expect(runner.instance_variable_get(:@options)[:scan_mode]).to eq(:diff)
      expect(runner.instance_variable_get(:@target_paths)).to be_empty
    end

    it "sets scan command with diff mode when only 'scan' command is given" do
      runner = Omamori::CoreRunner.new(["scan"])
      runner.send(:parse_options)
      expect(runner.instance_variable_get(:@options)[:command]).to eq(:scan)
      expect(runner.instance_variable_get(:@options)[:scan_mode]).to eq(:diff)
      expect(runner.instance_variable_get(:@target_paths)).to be_empty
    end

    it "sets scan command with paths mode and target paths when paths are given" do
      runner = Omamori::CoreRunner.new(["scan", "file1.rb", "dir/"])
      runner.send(:parse_options)
      expect(runner.instance_variable_get(:@options)[:command]).to eq(:scan)
      expect(runner.instance_variable_get(:@options)[:scan_mode]).to eq(:paths)
      expect(runner.instance_variable_get(:@target_paths)).to eq(["file1.rb", "dir/"])
    end

    it "parses --format option correctly" do
      runner = Omamori::CoreRunner.new(["scan", "--format", "json"])
      runner.send(:parse_options)
      expect(runner.instance_variable_get(:@options)[:format]).to eq(:json)
    end

    it "parses --ai option correctly" do
      runner = Omamori::CoreRunner.new(["scan", "--ai"])
      runner.send(:parse_options)
      expect(runner.instance_variable_get(:@options)[:only_ai]).to be true
    end

    it "parses --force-scan-ignored option correctly" do
      runner = Omamori::CoreRunner.new(["scan", "--force-scan-ignored"])
      runner.send(:parse_options)
      expect(runner.instance_variable_get(:@options)[:force_scan_ignored]).to be true
    end

    it "parses options and paths correctly when mixed" do
      runner = Omamori::CoreRunner.new(["scan", "--format", "html", "file1.rb", "--ai", "dir/"])
      runner.send(:parse_options)
      expect(runner.instance_variable_get(:@options)[:command]).to eq(:scan)
      expect(runner.instance_variable_get(:@options)[:scan_mode]).to eq(:paths)
      expect(runner.instance_variable_get(:@options)[:format]).to eq(:html)
      expect(runner.instance_variable_get(:@options)[:only_ai]).to be true
      expect(runner.instance_variable_get(:@target_paths)).to eq(["file1.rb", "dir/"])
    end

    it "sets scan mode to all when --all option is used" do
      runner = Omamori::CoreRunner.new(["scan", "--all"])
      runner.send(:parse_options)
      expect(runner.instance_variable_get(:@options)[:command]).to eq(:scan)
      expect(runner.instance_variable_get(:@options)[:scan_mode]).to eq(:all)
      expect(runner.instance_variable_get(:@target_paths)).to be_empty # --all should ignore paths if present, but test without paths first
    end

    it "sets scan mode to diff when --diff option is used (explicitly)" do
      runner = Omamori::CoreRunner.new(["scan", "--diff"])
      runner.send(:parse_options)
      expect(runner.instance_variable_get(:@options)[:command]).to eq(:scan)
      expect(runner.instance_variable_get(:@options)[:scan_mode]).to eq(:diff)
      expect(runner.instance_variable_get(:@target_paths)).to be_empty
    end

  end
end