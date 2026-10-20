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

- ステージされた変更（`git diff --staged`）、コードベース全体、または指定されたファイルやディレクトリをスキャンしてセキュリティリスクを検出
- BrakemanやBundler-Auditなどの静的解析ツールと連携
- AI（Gemini、Claude、OpenAIなど、RubyLLMが対応するLLMや、Claude Code・Codexのサブスクリプション）による高度なコード脆弱性検出
- 複数のレポート形式に対応（コンソール、HTML、JSON）
- `.omamorirc`ファイルによる柔軟な設定が可能
- `.omamoriignore`ファイルによるスキャン対象からの除外機能（`diff`モードを除く）

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

生成された`.omamorirc`ファイルと`.omamoriignore`ファイルを編集して、使用するLLMとモデル、実行するチェック項目、スキャン対象から除外するファイル/ディレクトリなどを設定します。

### スキャン

ステージされた変更をスキャン（デフォルト）：

```bash
omamori scan
```

ブランチの差分をスキャン（`main...HEAD`。プルリクエストに含まれる変更。CI向け）：

```bash
omamori scan --base main
```

コードベース全体をスキャン：

```bash
omamori scan --all
```
このモードでは`.omamoriignore`ファイルが有効になります。

出力形式を指定（コンソール、HTML、JSON）：

```bash
bundle exec omamori scan --format html
bundle exec omamori scan --all --format json
```

### ファイル/ディレクトリ指定スキャン

特定のファイルやディレクトリを指定してスキャンを実行します。

```bash
omamori scan <ファイルパス1> <ファイルパス2> ... <ディレクトリパス1> ...
```

例:

```bash
omamori scan app/controllers/users_controller.rb app/models/user.rb config/routes.rb lib/
```

このモードでは`.omamoriignore`ファイルが有効になります。

### AI解析のみ実施

静的解析ツールを使わず、AI解析のみを実行するには、`--ai`オプションを使用します：

```bash
omamori scan --ai
```

### 判定モデルによる高速チェック（Jev / OpenAI Decisions）

`--engine` に `jev` または `openai` を指定すると、セキュリティチェックを1項目ずつ、独立したyes/no判定として高速な判定モデルで実行します。

```bash
omamori scan --base main --engine jev
omamori scan --base main --engine openai
```

1. 差分をファイルごとに分け、各ファイルについて全チェック項目（既定は35項目）を1リクエストでまとめて判定モデルに問い合わせます。ファイル同士は並列に処理します。
2. 判定モデルが返す「脆弱性がある確率」が閾値未満の項目は、その場で通過とします。
3. 閾値以上の項目だけ、LLMがその脆弱性の詳細な検出手順に沿ってレポートを書きます。

判定モデルへの質問には、LLMに渡しているのと同じ脆弱性の定義と検出手順を含めています。判定モデルがエラーを返したファイルは、全項目をLLMに回します。LLMがレポートを書けなかった項目も、判定モデルの検出結果として残します（判定を黙って飛ばしません）。

| engine | 判定モデル | 判定モデルのAPIキー |
| --- | --- | --- |
| `llm`（既定） | なし。LLMが全項目を一度に判定 | なし |
| `jev` | TypeSafe Jev | `TYPESAFE_API_KEY` |
| `openai` | OpenAI Decisions API（`gpt-6-luna`） | `OPENAI_API_KEY` |

`jev` は `decision.jev.base_url` を変えることで、SystemOneプロトコルに対応した他のサーバーにも向けられます。以前の `engine: gemini` は `llm` と同じ意味で、そのまま使えます。

### LLMを選ぶ

レポートを書くLLM（`--engine llm` のときは、全項目を判定するLLM）は `--llm` で選びます。

```bash
omamori scan --base main --engine jev                # レポートは model に指定したモデル（既定 gemini-3.8-flash）
omamori scan --base main --engine jev --llm claude   # レポートは claude -p
omamori scan --base main --engine jev --llm codex    # レポートは codex exec
omamori scan --llm claude                            # 判定もレポートも claude -p
```

| llm | 呼び出すもの |
| --- | --- |
| `api`（既定） | [RubyLLM](https://rubyllm.com) 経由のAPI。`model` に指定したモデルを使い、Gemini、Anthropic、OpenAI、OpenRouter、Ollamaなど、RubyLLMが対応するプロバイダならどれでも使えます |
| `claude` | `claude -p`（サブスクリプション）。ツールをすべて無効にし、空の一時ディレクトリで実行 |
| `codex` | `codex exec`（サブスクリプション）。読み取り専用のサンドボックスで、空の一時ディレクトリで実行 |

`api` のAPIキーは、各プロバイダの環境変数（`GEMINI_API_KEY`、`ANTHROPIC_API_KEY`、`OPENAI_API_KEY`、`OPENROUTER_API_KEY` など、RubyLLMの設定名を大文字にしたもの）から読みます。モデル名だけでプロバイダが決まらない場合や、RubyLLMのモデル一覧にないモデルを使う場合は、`provider` も指定してください。以前の `llm: gemini` は `api` と同じ意味で、そのまま使えます。

diffには外部から来たコードが含まれるため、CLIはコマンドを実行できない状態で動かします。サブスクリプションのレート制限を考慮して、CLIを使うときのレポートの並列数は既定で3です（`decision.report_concurrency` で変更できます）。

各エンジンの検出精度は、`evals/` の問題集（35項目それぞれに脆弱なケースと惜しいけど安全なケース、および無害な変更）で測れます。使い方は [evals/README.md](evals/README.md) を参照してください。

## 設定

プロジェクトルートにある`.omamorirc`ファイルで、Omamoriの動作をカスタマイズできます。

設定項目の詳細は以下の通りです：

```yaml
# .omamorirc
# omamori用設定ファイル

# AIエンジン（任意、デフォルト: llm）。--engine で上書きできます
# engine: jev

# LLM（任意、デフォルト: api）。--llm で上書きできます
# llm: api

# llm が api のときに使うモデル（任意、デフォルト: gemini-3.8-flash）
# model: claude-sonnet-5-5
# provider: anthropic   # 任意。モデル名からプロバイダが決まらないときに指定

# Gemini APIキー（任意）。環境変数 GEMINI_API_KEY を推奨
# api_key: YOUR_GEMINI_API_KEY

# llm が claude / codex のときの設定（任意）
# claude:
#   model: sonnet       # 省略するとCLIの既定モデル
# codex:
#   model: gpt-5.5      # 省略するとCLIの既定モデル

# 判定モデルの設定（engine が jev / openai のとき）
# decision:
#   threshold: 0.3          # この確率以上の項目をLLMのレポートに回す
#   concurrency: 8          # 判定モデルに同時に投げるリクエスト数
#   report_concurrency: 3   # レポートを並列で書く数（CLIの既定は3、APIの既定は8）
#   jev:
#     model: jev-1.13.0     # 閾値を調整するなら、jev-latest ではなく版を固定する
#     base_url: https://api.typesafe.ai
#   openai:
#     model: gpt-6-luna

# 実行するセキュリティチェック（任意。デフォルトは engine: llm で主要6項目、jev / openai で全35項目）
# checks:
#   - xss
#   - csrf
#   - idor

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

- `engine`: `llm`、`jev`、`openai` のいずれか。デフォルトは`llm`（`gemini` も同じ意味）。
- `llm`: `api`、`claude`、`codex` のいずれか。デフォルトは`api`（`gemini` も同じ意味）。
- `model`: `llm: api` で使うモデル。RubyLLMが対応するモデルなら何でも指定できます。デフォルトは`gemini-3.8-flash`。
- `provider`: `llm: api` で使うRubyLLMのプロバイダ（`gemini`、`anthropic`、`openai` など）。任意。
- `api_key`: Gemini APIキー。環境変数`GEMINI_API_KEY`で渡すことを推奨します。他のプロバイダのキーは環境変数で渡します。
- `claude` / `codex`: CLIを使うときの`model`と`command`（CLIのパス）。
- `decision`: 判定モデルの設定。`threshold`（デフォルト0.3）、`concurrency`（デフォルト8）、`report_concurrency`、エンジンごとの`model`・`base_url`・`api_key`。APIキーは環境変数`TYPESAFE_API_KEY`、`OPENAI_API_KEY`で渡すことを推奨します。
- `checks`: 実行するセキュリティチェックのリスト。
- `prompt_templates`: AI解析用のカスタムプロンプトテンプレートを設定。
- `report`: レポート出力に関する設定。
  - `output_path`: HTMLおよびJSONレポートの出力先ディレクトリまたはプレフィックス。
  - `html_template`: カスタムHTMLテンプレート（ERB形式）のパス。
- `static_analysers`: 静的解析ツール（Brakeman、Bundler-Auditなど）の追加オプション設定。
- `language`: AI解析結果の詳細説明文の言語設定。デフォルトは英語（`en`）。

## .omamoriignore ファイル

`.omamoriignore`ファイルを使用すると、特定のファイルやディレクトリをスキャン対象から除外できます。ただし、`--force_scan_ignored`オプションを指定した場合は、このファイルの設定は無視されます。これは`.gitignore`ファイルと似たような働きをしますが、以下の点に注意してください。

*   **有効なモード:** `--all` モード、またはファイル/ディレクトリを指定してスキャンする場合にのみ有効です。
*   **無効なモード:** `diff` モード（引数なしの `omamori scan`）では、`.omamoriignore` ファイルは無視されます。これは、`git diff` で取得された変更点のみを対象とするためです。
*   **書式:** 1行に1つのパターンを記述します。`#` で始まる行はコメントとして扱われます。ディレクトリを指定する場合は、末尾に `/` を付けることを推奨します (例: `vendor/`)。単純な前方一致で評価されます。 (例: `config/initializers` は `config/initializers/devise.rb` にマッチします)ワイルドカード (`*`) は現時点ではサポートされていません。

`omamori init` コマンドを実行すると、一般的なRailsプロジェクトで無視すべきファイルやディレクトリのパターンが記述された`.omamoriignore`ファイルが生成されます。必要に応じてこのファイルを編集してください。

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
