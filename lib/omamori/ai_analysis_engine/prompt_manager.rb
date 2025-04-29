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
        回答は%{language}でお願いします。

        【解析対象コード】:
        %{code_content}
      TEXT

      RISK_PROMPTS = {
        xss: "Cross-Site Scripting (XSS): A vulnerability where user input is not properly escaped and is embedded into HTML or JavaScript, leading to arbitrary script execution in the victim’s browser. Look for unsanitized input and missing output encoding.",
        csrf: "Cross-Site Request Forgery (CSRF): An attack that forces an authenticated user to perform unwanted actions via forged requests. Detect missing CSRF tokens or absence of referer/origin validation.",
        idor: "Insecure Direct Object Reference (IDOR): Occurs when object identifiers (e.g., IDs) are exposed and access control is missing, allowing unauthorized access to other users’ data.",
        open_redirect: "Open Redirect: Redirecting users to external URLs based on user-supplied input without proper validation. Check for lack of domain or whitelist restrictions.",
        ssrf: "Server-Side Request Forgery (SSRF): The server makes HTTP requests to an arbitrary destination supplied by the user, potentially exposing internal resources or metadata.",
        session_fixation: "Session Fixation: The server accepts a pre-supplied session ID, allowing an attacker to hijack the session after authentication. Look for missing session ID regeneration after login.",
        inappropriate_cookie_attributes: "Insecure Cookie Attributes: Missing HttpOnly, Secure, or SameSite flags, which may lead to session theft or CSRF.",
        insufficient_encryption: "Insufficient Encryption: Use of weak algorithms (e.g., MD5, SHA1) or lack of encryption for sensitive data. Check for insecure hash functions or plain-text handling.",
        insecure_deserialization_rce: "Insecure Deserialization leading to RCE: Deserializing untrusted data can lead to arbitrary code execution. Detect unsafe use of deserialization functions without validation.",
        directory_traversal: "Directory Traversal: Allows attackers to access files outside the intended directory using ../ patterns. Check for path manipulation and missing canonicalization.",
        dangerous_eval: "Dangerous Code Execution (eval, exec): Dynamic code execution using untrusted input, allowing arbitrary code injection.",
        inappropriate_file_permissions: "Insecure File Permissions: Files or directories with overly permissive modes (e.g., 777), allowing unauthorized read/write/execute access.",
        temporary_backup_file_leak: "Temporary or Backup File Exposure: Sensitive files like .bak, .tmp, or ~ versions are publicly accessible due to poor file handling.",
        overly_detailed_errors: "Excessive Error Information Disclosure: Stack traces or internal error messages exposed to users, leaking implementation details.",
        csp_not_set: "Missing Content Security Policy (CSP): Absence of CSP headers increases risk of XSS. Look for missing Content-Security-Policy header.",
        mime_sniffing_vulnerability: "MIME Sniffing Vulnerability: Missing X-Content-Type-Options: nosniff header can allow browsers to misinterpret content types.",
        clickjacking_vulnerability: "Clickjacking Protection Missing: Absence of X-Frame-Options or frame-ancestors directive allows malicious framing of pages.",
        auto_index_exposure: "Auto Indexing Enabled: Directory listing is active, exposing files and internal structure to users.",
        inappropriate_password_policy: "Weak Password Policy: Inadequate rules such as short length, lack of complexity, or missing brute-force protections.",
        two_factor_auth_missing: "Missing Two-Factor Authentication (2FA): Lack of secondary authentication factor for sensitive operations.",
        race_condition: "Race Condition: Concurrent access without proper locking can lead to inconsistent states or privilege escalation.",
        server_error_information_exposure: "Server Error Information Exposure: Internal errors (e.g., 500) reveal stack traces or server information in responses.",
        dependency_trojan_package: "Dependency Trojan Package Risk: Installation of malicious or typosquatted packages from untrusted sources.",
        api_overexposure: "Excessive API Exposure: Public APIs exposed without authentication, leading to data leakage or unauthorized access.",
        security_middleware_disabled: "Security Middleware Disabled: Important protections (e.g., CSRF tokens, input sanitization) are turned off or removed.",
        security_header_inconsistency: "Security Header Inconsistency: Inconsistent or missing security headers across environments or routes.",
        excessive_login_attempts: "Excessive Login Attempts Allowed: Lack of rate limiting allows brute-force login attempts.",
        inappropriate_cache_settings: "Insecure Cache Settings: Sensitive pages are cached publicly (e.g., with Cache-Control: public), risking data leakage.",
        secret_key_committed: "Secret Key Committed to Repository: Credentials, JWT secrets, or API keys are hardcoded or pushed to version control.",
        third_party_script_validation_missing: "Missing Validation for Third-Party Scripts: External scripts are loaded without integrity checks (e.g., Subresource Integrity).",
        over_logging: "Over-Logging: Logging sensitive information such as passwords, tokens, or personal data.",
        fail_open_design: "Fail-Open Design: On error or exception, access is granted instead of safely denied.",
        environment_differences: "Uncontrolled Environment Differences: Security settings differ between development and production without strict controls.",
        audit_log_missing: "Missing Audit Logging: Lack of logging for critical actions or authorization checks prevents accountability.",
        time_based_side_channel: "Time-Based Side Channel: Execution time differences can leak secrets (e.g., timing attacks in string comparison)."
      }.freeze
      

      def initialize(config = {})
        # Load custom templates and language from config, merge with default
        custom_templates = config.get("prompt_templates", {}) # Use get instead of fetch
        @prompt_templates = { default: DEFAULT_PROMPT_TEMPLATE }.merge(custom_templates)
        @risk_prompts = RISK_PROMPTS
        @language = config.get("language", "en") # Get language from config, default to 'en'
      end

      def build_prompt(code_content, risks_to_check, json_schema, template_key: :default)
        # Use the template from @prompt_templates, defaulting to :default if template_key is not found
        template = @prompt_templates.fetch(template_key, @prompt_templates[:default])
        risk_list = risks_to_check.map { |risk_key| @risk_prompts[risk_key] }.compact.join(", ")

        template % { risk_list: risk_list, code_content: code_content, json_schema: json_schema.to_json, language: @language}
      end
    end
  end
end