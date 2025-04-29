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
        xss:                           "XSS（クロスサイトスクリプティング）：ユーザー入力が適切にエスケープされず HTML や JavaScript に埋め込まれ、他ユーザーのブラウザ上で任意スクリプトが実行される脆弱性。入力値のサニタイズ漏れや出力時エンコーディング不備を検知。",
        csrf:                          "CSRF（クロスサイトリクエストフォージェリ）：ユーザーの認証済みセッションを悪用し、意図しないリクエストを第三者サイトから実行させる攻撃。トークン検証不足や Referer チェック漏れパターンを検出。",
        idor:                          "IDOR（Insecure Direct Object Reference）：アクセス制御チェックなしに連番や直接的なオブジェクト参照を行い、他ユーザーのデータを取得・操作できる脆弱性。パラメータ値の検証・権限チェック漏れを見つける。",
        open_redirect:                 "オープンリダイレクト：外部サイトへのリダイレクト先をパラメータで受け取り、正当性検証なしに転送する脆弱性。ホワイトリストチェックやドメイン制限の欠如を検知。",
        ssrf:                          "SSRF（Server-Side Request Forgery）：外部から指定された URL にサーバー自身がリクエストを送信し、内部ネットワーク資源やメタデータを不正取得する脆弱性。URL バリデーション不足を検出。",
        session_fixation:              "セッション固定（Session Fixation）：攻撃者があらかじめ用意したセッション ID を利用者に使わせ、認証後も同一セッションでアクセスさせる設計上の欠陥。セッション再生成漏れを検出。",
        inappropriate_cookie_attributes: "不適切なクッキー属性：HttpOnly, Secure, SameSite といった重要属性が未設定で、XSS や CSRF、セッションハイジャックを許す設定ミスを検知。",
        insufficient_encryption:       "不十分な暗号化設定：MD5 や SHA1 といった脆弱なハッシュ、平文送信や鍵長不足の暗号を利用しているパターンを検出。",
        insecure_deserialization_rce:   "インセキュアなデシリアライズによる RCE：外部入力をそのままオブジェクト復元に使い、任意コード実行を招く。信頼しないデータのデシリアライズ箇所を見つける。",
        directory_traversal:           "ディレクトリ・トラバーサル：パスに「../」などを含めることで上位ディレクトリへ不正アクセスする脆弱性。入力パスの正規化・バリデーション不足を検出。",
        dangerous_eval:                "危険な eval／動的コード実行：ユーザー入力を eval, exec, new Function などで評価し、任意コード実行可能となるコードを検出。",
        inappropriate_file_permissions:  "不適切なファイルパーミッション：ファイルやディレクトリが 777 モードなどで公開され、意図しない読み書き・削除を許可している設定ミスを検出。",
        temporary_backup_file_leak:     "テンポラリ・バックアップファイルの漏洩：*.bak, *.tmp, ~ ファイルが公開ディレクトリに残存し、ソースコードや機密情報が流出するパターンを検知。",
        overly_detailed_errors:        "詳細すぎるエラーメッセージ：スタックトレースや SQL 文、ファイルパスなど内部情報をクライアントへ出力している箇所を検出。",
        csp_not_set:                   "CSP（Content Security Policy）未設定：XSS 防御のための CSP ヘッダーがレスポンスに含まれていないパターンを検出。",
        mime_sniffing_vulnerability:   "MIME スニッフィング対策漏れ：X-Content-Type-Options: nosniff が未設定で、ブラウザがコンテンツを誤解釈するリスクを検知。",
        clickjacking_vulnerability:    "クリックジャッキング対策漏れ：X-Frame-Options や Content-Security-Policy: frame-ancestors が未設定・不適切で、クリックジャッキングを許す箇所を検出。",
        auto_index_exposure:           "オートインデックス公開：ディレクトリリスティングが有効化され、ファイル一覧が外部から参照可能な設定ミスを検知。",
        inappropriate_password_policy: "不適切なパスワードポリシー：最小文字数不足、複雑性ルール欠如、ブルートフォース防御なしのパターンを検出。",
        two_factor_auth_missing:       "二要素認証未導入：認証フローに SMS や TOTP など 2FA 要素が存在せず、認証強度が低い箇所を検出。",
        race_condition:                "レースコンディション：並行アクセスで不整合状態を招くロック・排他制御不足のコードを検出。",
        server_error_information_exposure: "サーバーエラー情報の曝露：500 エラー応答時に詳細情報を出力し、内部実装情報を漏出している箇所を検出。",
        dependency_trojan_package:     "依存関係のトロージャンパッケージ：npm, pip 等で公式外や名前詐称パッケージをインストールしているリスクを検出。",
        api_overexposure:              "API 過剰公開：認証不要のエンドポイントや過剰なデータ返却を行い、情報漏洩を招く実装を検出。",
        security_middleware_disabled:  "セキュリティミドルウェア無効化：CSRF 保護や入力サニタイズをオフにしている設定箇所を検出。",
        security_header_inconsistency: "セキュリティヘッダー未統一：XSS, CSRF 防御ヘッダーの欠如や環境ごとの不整合を検出。",
        excessive_login_attempts:      "過剰なログイン試行許可：レートリミット未設定でブルートフォース攻撃を受けやすい実装を検出。",
        inappropriate_cache_settings:  "不適切なキャッシュ設定：認証ページに public キャッシュを設定し、機密情報をキャッシュさせる設定ミスを検出。",
        secret_key_committed:          "秘密鍵・JWT シークレットのコミット：リポジトリに .env や設定ファイルで秘密情報を直接書き込んでいる差分を検出。",
        third_party_script_validation_missing: "サードパーティスクリプト検証欠如：外部スクリプト読み込み時の署名・ハッシュ検証を行っていない実装を検出。",
        over_logging:                  "オーバーロギング：パスワードやトークンなど機密情報をログ出力している箇所を検出。",
        fail_open_design:              "フェイルオープン設計：エラー時に安全拒否ではなく許可動作するコードパスを検出。",
        environment_differences:       "環境間設定差異放置：開発／本番でセキュリティ設定が異なるままデプロイしている差分を検出。",
        audit_log_missing:             "監査ログ欠如：重要操作や認可チェック結果をログに記録していない箇所を検出。",
        time_based_side_channel:       "タイムベースのサイドチャネル：処理時間差で秘密情報を推測可能な実装を検出（例：文字列比較のタイミング差）。",
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