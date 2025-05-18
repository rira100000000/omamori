# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_analysis_engine/diff_splitter'

RSpec.describe Omamori::AIAnalysisEngine::DiffSplitter do
  let(:chunk_size) { 100 }
  let(:gemini_client_double) { instance_double(Omamori::AIAnalysisEngine::GeminiClient) }
  let(:prompt_manager_double) { instance_double(Omamori::AIAnalysisEngine::PromptManager) }
  let(:json_schema) { { type: "object", properties: { security_risks: { type: "array" } } } }
  let(:risks_to_check) { [:xss, :csrf] }

  describe "#initialize" do
    it "initializes with the default chunk size if none is provided" do
      splitter = Omamori::AIAnalysisEngine::DiffSplitter.new
      expect(splitter.instance_variable_get(:@chunk_size)).to eq(Omamori::AIAnalysisEngine::DiffSplitter::DEFAULT_CHUNK_SIZE)
    end

    it "initializes with the provided chunk size" do
      splitter = Omamori::AIAnalysisEngine::DiffSplitter.new(chunk_size: chunk_size)
      expect(splitter.instance_variable_get(:@chunk_size)).to eq(chunk_size)
    end
  end

  describe "#split" do
    let(:splitter) { Omamori::AIAnalysisEngine::DiffSplitter.new(chunk_size: 50) }

    it "splits content into chunks based on chunk size" do
      content = "Line 1\n" + ("a" * 40) + "\nLine 3\n" + ("b" * 40) + "\nLine 5"
      # Chunk 1: "Line 1\n" + ("a" * 40) + "\n" (length 7 + 40 + 1 = 48, fits)
      # Chunk 2: "Line 3\n" + ("b" * 40) + "\n" (length 7 + 40 + 1 = 48, fits)
      # Chunk 3: "Line 5" (length 6, fits)
      expected_chunks = [
        "Line 1\n" + ("a" * 40) + "\n",
        "Line 3\n" + ("b" * 40) + "\n",
        "Line 5"
      ]
      expect(splitter.split(content)).to eq(expected_chunks)
    end

    it "handles content smaller than chunk size" do
      content = "This is a short line."
      expect(splitter.split(content)).to eq([content])
    end

    it "handles content exactly the chunk size" do
      content = "a" * 50
      expect(splitter.split(content)).to eq([content])
    end

    it "handles content slightly larger than chunk size, creating two chunks" do
      content = ("a" * 50) + "b"
      expect(splitter.split(content)).to eq([("a" * 50) + "b"])
    end


    it "handles empty content" do
      expect(splitter.split("")).to eq([])
    end

    it "handles content with only newlines" do
      content = "\n\n\n"
      expect(splitter.split(content)).to eq(["\n\n\n"])
    end
  end

  describe "#process_in_chunks" do
    let(:splitter) { Omamori::AIAnalysisEngine::DiffSplitter.new(chunk_size: 50) }
    let(:content) { "Line 1\n" + ("a" * 40) + "\nLine 3\n" + ("b" * 40) + "\nLine 5" }
    let(:chunk1) { "Line 1\n" + ("a" * 40) + "\n" } # Update chunk1 definition
    let(:chunk2) { "Line 3\n" + ("b" * 40) + "\n" } # Update chunk2 definition
    let(:chunk3) { "Line 5" }
    let(:chunk1_prompt) { "prompt for chunk 1" }
    let(:chunk2_prompt) { "prompt for chunk 2" }
    let(:chunk3_prompt) { "prompt for chunk 3" }
    let(:chunk1_result) { { "security_risks" => [{ "risk" => "XSS", "severity" => "Medium" }] } }
    let(:chunk2_result) { { "security_risks" => [{ "risk" => "CSRF", "severity" => "High" }] } }
    let(:chunk3_result) { { "security_risks" => [{ "risk" => "SSRF", "severity" => "Low" }] } }

    before do
      allow(prompt_manager_double).to receive(:build_prompt).with(chunk1, risks_to_check, json_schema, file_path: anything).and_return(chunk1_prompt)
      allow(prompt_manager_double).to receive(:build_prompt).with(chunk2, risks_to_check, json_schema, file_path: anything).and_return(chunk2_prompt)
      allow(prompt_manager_double).to receive(:build_prompt).with(chunk3, risks_to_check, json_schema, file_path: anything).and_return(chunk3_prompt)


      # Allow puts for output
      allow_any_instance_of(Object).to receive(:puts)
    end

    it "splits the content, processes each chunk, and combines results" do
      allow(gemini_client_double).to receive(:analyze).with(chunk1_prompt, json_schema, model: "gemini-2.5-flash-preview-04-17").and_return(chunk1_result)
      allow(gemini_client_double).to receive(:analyze).with(chunk2_prompt, json_schema, model: "gemini-2.5-flash-preview-04-17").and_return(chunk2_result)
      allow(gemini_client_double).to receive(:analyze).with(chunk3_prompt, json_schema, model: "gemini-2.5-flash-preview-04-17").and_return(chunk3_result)

      expect(splitter).to receive(:split).with(content).and_call_original
      expect(prompt_manager_double).to receive(:build_prompt).exactly(3).times
      expect(gemini_client_double).to receive(:analyze).exactly(3).times
      expect(splitter).to receive(:combine_results).with([chunk1_result, chunk2_result, chunk3_result]).and_call_original

      result = splitter.process_in_chunks(content, gemini_client_double, json_schema, prompt_manager_double, risks_to_check)

      expected_combined_risks = chunk1_result["security_risks"] + chunk2_result["security_risks"] + chunk3_result["security_risks"]
      expect(result).to eq({ "security_risks" => expected_combined_risks })
    end

    it "handles content smaller than chunk size without splitting" do
      short_content = "Short content."
      short_prompt = "prompt for short content"
      short_result = { "security_risks" => [{ "risk" => "IDOR", "severity" => "Low" }] }

      allow(prompt_manager_double).to receive(:build_prompt).with(short_content, risks_to_check, json_schema, file_path: anything).and_return(short_prompt)
      allow(gemini_client_double).to receive(:analyze).with(short_prompt, json_schema, model: "gemini-2.5-flash-preview-04-17").and_return(short_result)

      expect(splitter).to receive(:split).with(short_content).and_call_original
      expect(prompt_manager_double).to receive(:build_prompt).once
      expect(gemini_client_double).to receive(:analyze).once
      expect(splitter).to receive(:combine_results).with([short_result]).and_call_original

      result = splitter.process_in_chunks(short_content, gemini_client_double, json_schema, prompt_manager_double, risks_to_check)
      expect(result).to eq(short_result)
    end

    it "handles empty content" do
      expect(splitter).to receive(:split).with("").and_return([])
      expect(prompt_manager_double).not_to receive(:build_prompt)
      expect(gemini_client_double).not_to receive(:analyze)
      expect(splitter).to receive(:combine_results).with([]).and_call_original

      result = splitter.process_in_chunks("", gemini_client_double, json_schema, prompt_manager_double, risks_to_check)
      expect(result).to eq({ "security_risks" => [] })
    end

    it "handles nil results from analyze" do
      allow(prompt_manager_double).to receive(:build_prompt).with(anything, anything, json_schema, file_path: anything).and_return("dummy prompt")
      allow(gemini_client_double).to receive(:analyze).with(anything, json_schema, model: "gemini-2.5-flash-preview-04-17").and_return(chunk1_result, nil, chunk2_result) # Simulate one nil result

      expect(splitter).to receive(:combine_results).with([chunk1_result, nil, chunk2_result]).and_call_original

      result = splitter.process_in_chunks(content, gemini_client_double, json_schema, prompt_manager_double, risks_to_check)

      expected_combined_risks = chunk1_result["security_risks"] + chunk2_result["security_risks"]
      expect(result).to eq({ "security_risks" => expected_combined_risks })
    end

    it "handles results without 'security_risks' key" do
      result_without_risks = { "other_data" => "..." }
      allow(prompt_manager_double).to receive(:build_prompt).with(anything, anything, json_schema, file_path: anything).and_return("dummy prompt")
      allow(gemini_client_double).to receive(:analyze).with(anything, json_schema, model: "gemini-2.5-flash-preview-04-17").and_return(chunk1_result, result_without_risks, chunk2_result) # Simulate one result without risks

      expect(splitter).to receive(:combine_results).with([chunk1_result, result_without_risks, chunk2_result]).and_call_original

      result = splitter.process_in_chunks(content, gemini_client_double, json_schema, prompt_manager_double, risks_to_check)

      expected_combined_risks = chunk1_result["security_risks"] + chunk2_result["security_risks"]
      expect(result).to eq({ "security_risks" => expected_combined_risks })
    end
  end

  describe "#combine_results" do
    let(:splitter) { Omamori::AIAnalysisEngine::DiffSplitter.new }

    it "flattens security_risks from multiple results" do
      results = [
        { "security_risks" => [{ "risk" => "XSS", "severity" => "Medium" }] },
        { "security_risks" => [{ "risk" => "CSRF", "severity" => "High" }] },
        { "security_risks" => [{ "risk" => "IDOR", "severity" => "Low" }] }
      ]
      expected_combined_risks = results.flat_map { |r| r["security_risks"] }
      expect(splitter.__send__(:combine_results, results)).to eq({ "security_risks" => expected_combined_risks })
    end

    it "handles results with nil or missing security_risks key" do
      results = [
        { "security_risks" => [{ "risk" => "XSS", "severity" => "Medium" }] },
        nil,
        { "other_data" => "..." },
        { "security_risks" => [{ "risk" => "CSRF", "severity" => "High" }] }
      ]
      expected_combined_risks = [
        { "risk" => "XSS", "severity" => "Medium" },
        { "risk" => "CSRF", "severity" => "High" }
      ]
      expect(splitter.__send__(:combine_results, results)).to eq({ "security_risks" => expected_combined_risks })
    end

    it "handles an empty list of results" do
      expect(splitter.__send__(:combine_results, [])).to eq({ "security_risks" => [] })
    end
  end
end
