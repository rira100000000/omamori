# frozen_string_literal: true

module Omamori
  module AIAnalysisEngine
    class PromptManager
      # TODO: Load prompt templates from config file
      DEFAULT_PROMPT_TEMPLATE = <<~TEXT
        あなたはRubyのセキュリティ専門家です。以下のコードを解析し、潜在的なセキュリティリスクを検出してください。
        特に以下の種類の脆弱性に注目してください: %{risk_list}
        検出したリスクは、以下のJSON Schemaの形式で報告してください。
        %{json_schema}
        リスクが見つからない場合は、"security_risks"配列を空のリストとして出力してください。

        【解析対象コード】:
        %{code_content}
      TEXT

      RISK_PROMPTS = {
        xss: "XSS（クロスサイトスクリプティング）",
        csrf: "CSRF（クロスサイトリクエストフォージェリ）",
        idor: "IDOR（Insecure Direct Object Reference）",
        open_redirect: "オープンリダイレクト",
        ssrf: "SSRF（Server-Side Request Forgery）",
        session_fixation: "セッション固定（Session Fixation）",
        # TODO: Add other risks from requirements
      }.freeze

      def initialize(config = {})
        # Load custom templates from config, merge with default
        custom_templates = config.fetch("prompt_templates", {})
        @prompt_templates = { default: DEFAULT_PROMPT_TEMPLATE }.merge(custom_templates)
        @risk_prompts = RISK_PROMPTS
      end

      def build_prompt(code_content, risks_to_check, json_schema, template_key: :default)
        # Use the template from @prompt_templates, defaulting to :default if template_key is not found
        template = @prompt_templates.fetch(template_key, @prompt_templates[:default])
        risk_list = risks_to_check.map { |risk_key| @risk_prompts[risk_key] }.compact.join(", ")

        template % { risk_list: risk_list, code_content: code_content, json_schema: json_schema.to_json }
      end
    end
  end
end