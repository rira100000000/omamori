# frozen_string_literal: true

require 'spec_helper'
require 'omamori/ai_analysis_engine/prompt_manager'

RSpec.describe Omamori::AIAnalysisEngine::PromptManager do
  let(:default_template) { Omamori::AIAnalysisEngine::PromptManager::DEFAULT_PROMPT_TEMPLATE }
  let(:risk_prompts) { Omamori::AIAnalysisEngine::PromptManager::RISK_PROMPTS }

  describe "#initialize" do
    it "initializes with default prompt template if no config is provided" do
      manager = Omamori::AIAnalysisEngine::PromptManager.new
      expect(manager.instance_variable_get(:@prompt_templates)).to eq({ default: default_template })
      expect(manager.instance_variable_get(:@risk_prompts)).to eq(risk_prompts)
    end

    it "merges custom prompt templates from config" do
      custom_config = { "prompt_templates" => { "custom_scan" => "Custom scan template: %{code_content}" } }
      manager = Omamori::AIAnalysisEngine::PromptManager.new(custom_config)
      expected_templates = {
        default: default_template,
        "custom_scan" => "Custom scan template: %{code_content}"
      }
      expect(manager.instance_variable_get(:@prompt_templates)).to eq(expected_templates)
      expect(manager.instance_variable_get(:@risk_prompts)).to eq(risk_prompts)
    end

    it "uses default risk prompts if not specified in config (current behavior)" do
      # Current implementation doesn't allow overriding risk_prompts via config
      manager = Omamori::AIAnalysisEngine::PromptManager.new({})
      expect(manager.instance_variable_get(:@risk_prompts)).to eq(risk_prompts)
    end
  end

  describe "#build_prompt" do
    let(:code_content) { "def risky_method(input); eval(input); end" }
    let(:risks_to_check) { [:xss, :eval_injection] } # Assuming :eval_injection is a valid key in RISK_PROMPTS

    # Add :eval_injection to RISK_PROMPTS for this test context
    before do
      stub_const("Omamori::AIAnalysisEngine::PromptManager::RISK_PROMPTS", risk_prompts.merge(eval_injection: "コード評価（evalなど）"))
    end


    it "builds the prompt using the default template and provided data" do
      manager = Omamori::AIAnalysisEngine::PromptManager.new
      expected_risk_list = "XSS（クロスサイトスクリプティング）, コード評価（evalなど）"
      expected_prompt = default_template % { risk_list: expected_risk_list, code_content: code_content, json_schema: {}.to_json }
 
       prompt = manager.build_prompt(code_content, risks_to_check, {})
       expect(prompt).to eq(expected_prompt)
     end
 
     it "builds the prompt using a custom template if specified" do
       custom_template = "Custom template for %{risk_list}:\n%{code_content}"
       custom_config = { "prompt_templates" => { "custom_scan" => custom_template } }
       manager = Omamori::AIAnalysisEngine::PromptManager.new(custom_config)
 
       expected_risk_list = "XSS（クロスサイトスクリプティング）, コード評価（evalなど）"
       # Note: Custom template does not have %{json_schema}, so it's not included in the expected prompt
       expected_prompt = custom_template % { risk_list: expected_risk_list, code_content: code_content }
 
       prompt = manager.build_prompt(code_content, risks_to_check, {}, template_key: "custom_scan")
       expect(prompt).to eq(expected_prompt)
     end
 
     it "uses the default template if the specified template_key is not found" do
       manager = Omamori::AIAnalysisEngine::PromptManager.new
       expected_risk_list = "XSS（クロスサイトスクリプティング）, コード評価（evalなど）"
       expected_prompt = default_template % { risk_list: expected_risk_list, code_content: code_content, json_schema: {}.to_json }
 
       prompt = manager.build_prompt(code_content, risks_to_check, {}, template_key: :non_existent_template)
       expect(prompt).to eq(expected_prompt)
     end
 
     it "handles an empty risks_to_check list" do
       manager = Omamori::AIAnalysisEngine::PromptManager.new
       expected_risk_list = ""
       expected_prompt = default_template % { risk_list: expected_risk_list, code_content: code_content, json_schema: {}.to_json }
 
       prompt = manager.build_prompt(code_content, [], {})
       expect(prompt).to eq(expected_prompt)
     end
 
     it "ignores risk keys not present in RISK_PROMPTS" do
       manager = Omamori::AIAnalysisEngine::PromptManager.new
       risks_with_invalid = [:xss, :invalid_risk, :csrf]
       expected_risk_list = "XSS（クロスサイトスクリプティング）, CSRF（クロスサイトリクエストフォージェリ）"
       expected_prompt = default_template % { risk_list: expected_risk_list, code_content: code_content, json_schema: {}.to_json }
 
       prompt = manager.build_prompt(code_content, risks_with_invalid, {})
       expect(prompt).to eq(expected_prompt)
     end
  end
end