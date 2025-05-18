# Omamori Gem（お守りジェム）

Omamoriは、Rubyコードおよび依存関係に潜む潜在的なセキュリティ脆弱性を検出するRuby製のGemです。
初心者プログラマーが作りがちな脆弱性を診断することを目的としています。
静的解析ツールとAIによるコード解析を組み合わせることで柔軟な診断を可能とします。

ただし、このgemはあくまでも「お守り」であり、プログラムの安全を保証するものではありません。
人間がチェックした上で万が一に発生した脆弱性を、防いでくれる"かもしれません"。

注意:
AI解析は静的解析で診断できない脆弱性を発見することができますが、モデルの気分によって診断の精度にブレが生じやすいです。
複数回実行することで偽陰性を防ぐことができるかもしれません。

## 特徴

- ステージされた変更（`git diff --staged`）またはコードベース全体をスキャンしてセキュリティリスクを検出
- BrakemanやBundler-Auditなどの静的解析ツールと連携
- Gemini APIを活用し、AIによる高度なコード脆弱性検出
- 複数のレポート形式に対応（コンソール、HTML、JSON）
- `.omamorirc`ファイルによる柔軟な設定が可能

## インストール

アプリケーションのGemfileに以下を追加します：

```ruby
gem 'omamori'
```

その後、以下を実行します：

```bash
bundle install
```

または、個別にインストールする場合は：

```bash
gem install omamori
```

## 使い方

### 初期化

初期設定ファイル（`.omamorirc`）を生成するには、以下を実行します：

```bash
omamori init
```

生成された`.omamorirc`ファイルを編集して、Gemini APIキー、使用するモデル、実行するチェック項目などを設定します。

### スキャン

ステージされた変更をスキャン（デフォルト）：

```bash
omamori scan
```

コードベース全体をスキャン：

```bash
omamori scan --all
```

出力形式を指定（コンソール、HTML、JSON）：

```bash
bundle exec omamori scan --format html
bundle exec omamori scan --all --format json
```

### AI解析のみ実施

静的解析ツールを使わず、AI解析のみを実行するには、`--ai`オプションを使用します：

```bash
omamori scan --ai
```

## 設定

プロジェクトルートにある`.omamorirc`ファイルで、Omamoriの動作をカスタマイズできます。

設定項目の詳細は以下の通りです：

```yaml
# .omamorirc
# omamori用設定ファイル

# Gemini APIキー（AI解析に必須）
# 環境変数GEMINI_API_KEYで設定することも可能
api_key: YOUR_GEMINI_API_KEY # 実際のAPIキーに置き換えてください

# 使用するGeminiモデル（任意、デフォルト: gemini-2.5-flash-preview-04-17）
model: gemini-2.5-flash-preview-04-17

# 有効化するセキュリティチェック（任意、デフォルトは全チェック）
# checks:
#   xss: true
#   csrf: true
#   idor: true
#   ... # 他のチェック項目も追加可能

# カスタムプロンプトテンプレート（任意）
# prompt_templates:
#   default: |
#     ここにカスタムプロンプトを記述...

# レポート出力設定（任意）
# report:
#   output_path: ./omamori_report # HTML/JSONレポートの出力先ディレクトリまたは接頭辞
#   html_template: path/to/custom/template.erb # カスタムHTMLテンプレートのパス

# 静的解析ツールのオプション設定（任意）
# static_analysers:
#   brakeman:
#     options: "--force" # Brakemanに渡す追加オプション
#   bundler_audit:
#     options: "--quiet" # Bundler-Auditに渡す追加オプション

# AI解析時の詳細出力言語設定（任意、デフォルト: en）
# language: ja
```

- `api_key`: Gemini APIへのアクセスキー。環境変数`GEMINI_API_KEY`でも設定可能。
- `model`: AI解析に使用するGeminiモデル。デフォルトは`gemini-2.5-flash-preview-04-17`。
- `checks`: 実行するセキュリティチェックの設定。特定のチェックを有効/無効にできます（例：`xss: true`, `csrf: false`）。
- `prompt_templates`: AI解析用のカスタムプロンプトテンプレートを設定。
- `report`: レポート出力に関する設定。
  - `output_path`: HTMLおよびJSONレポートの出力先ディレクトリまたはプレフィックス。
  - `html_template`: カスタムHTMLテンプレート（ERB形式）のパス。
- `static_analysers`: 静的解析ツール（Brakeman、Bundler-Auditなど）の追加オプション設定。
- `language`: AI解析結果の詳細説明文の言語設定。デフォルトは英語（`en`）。

## デモファイル

`demo`ディレクトリには、Omamoriの機能をデモンストレーションするための既知の脆弱性を含むサンプルファイルが置かれています。

デモファイルを対象にOmamoriを実行するには、以下の手順を実施してください：

1. `demo`ディレクトリをコピーします：

    ```bash
    cp -r demo demo_
    ```

2. コピーした`demo_`ディレクトリをステージします：

    ```bash
    git add demo_
    ```

3. ステージしたデモファイルに対してOmamoriを実行します：

    ```bash
    omamori scan
    ```

    または、ステージ後にすべてのファイルをスキャンする場合：

    ```bash
    omamori scan --all
    ```

## 貢献について

バグ報告やプルリクエストはGitHubで歓迎しています。このプロジェクトは、安全かつ協力的なコラボレーションの場を目指しています。

## ライセンス

このGemは、[MITライセンス](https://opensource.org/licenses/MIT)のもとでオープンソースとして公開されています。
