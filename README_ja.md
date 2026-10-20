# Omamori Gem（お守りジェム）

Omamoriは、Rubyコードおよび依存関係に潜む潜在的なセキュリティ脆弱性を検出するRuby製のGemです。
初心者プログラマーが作りがちな脆弱性を診断することを目的としています。
静的解析ツールとAIによるコード解析を組み合わせることで柔軟な診断を可能とします。

ただし、このgemはあくまでも「お守り」であり、プログラムの安全を保証するものではありません。
人間がチェックした上で万が一に発生した脆弱性を、防いでくれる"かもしれません"。

注意:
AI解析は静的解析で診断できない脆弱性を発見することができますが、LLMの診断結果は実行のたびにブレが生じやすいです。
判定役（classifier）を使うと、37項目を1つずつ独立に判定するため、結果が比較的安定します。

## 特徴

- ステージされた変更（`git diff --staged`）、ブランチの差分（`--base`）、コードベース全体、または指定されたファイルやディレクトリをスキャン
- 37種類の脆弱性を1項目ずつyes/noで判定する高速チェック（TypeSafe Jev、OpenAI Decisionsなど）。引っかかった項目だけ、LLMが詳しいレポートを書きます
- 判定役とレポート役を、それぞれ自由に選べます。レポート役には、RubyLLMが対応するAPI（Gemini、Claude、OpenAIなど）のほか、Claude Code（`claude -p`）やCodex（`codex exec`）のサブスクリプションも使えます
- BrakemanやBundler-Auditなどの静的解析ツールと連携
- 複数のレポート形式に対応（コンソール、HTML、JSON）
- GitHub Actions / GitLab CI の設定ファイルを生成
- 検出精度を測るための問題集（`evals/`）
- `.omamorirc`ファイルによる設定と、`.omamoriignore`ファイルによるスキャン対象からの除外

## 仕組み

omamoriのAI解析は、2つの役割で動きます。

- **判定役（classifier）:** 37項目を1つずつyes/noで判定する、高速な判定モデルです。TypeSafe JevやOpenAI Decisionsなどがあります。使うかどうかは選べます。
- **レポート役（reporter）:** 脆弱性のレポートを書くLLMです。判定役を使わない場合は、レポート役が全項目を一度に判定します。

判定役を使うと、次の流れになります。

1. 差分をファイルごとに分け、各ファイルについて全チェック項目（既定は37項目）を1リクエストでまとめて判定役に問い合わせます。ファイル同士は並列に処理します。
2. 判定役が返す「脆弱性がある確率」が閾値未満の項目は、その場で通過とします。
3. 閾値以上の項目だけ、レポート役がその脆弱性の詳細な検出手順に沿ってレポートを書きます。

判定役への質問には、レポート役に渡しているのと同じ脆弱性の定義と検出手順を含めています。XSS、SQLインジェクション、Mass Assignmentは、「この変更に脆弱性があるか」という全体の問いに加えて、それ1つで脆弱と言える具体的な形（小項目。たとえばXSSなら「ユーザー由来のURLを、スキームを確認せずに `href` に入れていないか」）も1つずつ判定し、そのうち最も高い確率を使います。反応した小項目は、レポート役にも伝えます。判定役がエラーを返したファイルは、全項目をレポート役に回します。レポート役がレポートを書けなかった項目も、判定役の検出結果として残します（判定を黙って飛ばしません）。

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

生成された`.omamorirc`ファイルと`.omamoriignore`ファイルを編集して、判定役とレポート役、実行するチェック項目、スキャン対象から除外するファイル/ディレクトリなどを設定します。

### APIキーの設定

APIキーは環境変数で渡します。使う機能に応じて設定してください。

```bash
export GEMINI_API_KEY=...     # 既定のレポート役（gemini-3.8-flash）
export TYPESAFE_API_KEY=...   # 判定役に typesafe（Jev）を使う場合
export OPENAI_API_KEY=...     # 判定役に openai を使う場合
```

Gemini以外のレポート役を使う場合は、そのプロバイダの環境変数（`ANTHROPIC_API_KEY`、`OPENROUTER_API_KEY` など、RubyLLMの設定名を大文字にしたもの）を設定します。レポート役に `claude_code` / `codex` を使う場合は、インストール済みのCLIのログイン状態を使うので、APIキーは不要です。

### スキャン

おすすめは、ブランチの差分を判定役（Jev）でチェックする使い方です：

```bash
omamori scan --base main --classifier typesafe
```

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

特定のファイルやディレクトリを指定してスキャン：

```bash
omamori scan app/controllers/users_controller.rb app/models/user.rb config/routes.rb lib/
```
このモードでも`.omamoriignore`ファイルが有効になります。

出力形式を指定（コンソール、HTML、JSON）：

```bash
omamori scan --format html
omamori scan --all --format json
```

静的解析ツールを使わず、AI解析のみを実行：

```bash
omamori scan --ai
```

### 判定役とレポート役を選ぶ

どちらの役も `provider` と `model` で指定します。コマンドラインでも、`.omamorirc`（[設定](#設定)）でも指定できます。

```bash
omamori scan --base main --classifier typesafe                           # Jevで判定、Geminiでレポート
omamori scan --base main --classifier typesafe --reporter claude_code    # Jevで判定、claude -pでレポート
omamori scan --base main --classifier openai --reporter anthropic --reporter-model claude-sonnet-5-5
omamori scan --reporter codex                                            # 判定役なし。codex execで全項目を判定
```

**判定役（classifier）に指定できるprovider**

| provider | 判定モデル | APIキー |
| --- | --- | --- |
| `typesafe` | TypeSafe Jev（`model` 省略時は `jev-1.13.0`） | `TYPESAFE_API_KEY` |
| `openai` | OpenAI Decisions API（`model` 省略時は `gpt-6-luna`） | `OPENAI_API_KEY` |
| `ollama` | Ollamaで動かす判定モデル（Clefなど）。`model` と、接続先の `base_url`（または `OLLAMA_API_BASE`）が必須 | なし |
| `none` | 判定役を使わない（既定） | なし |

`base_url` を指定すると、SystemOneプロトコルに対応した他のサーバーにも向けられます。

**レポート役（reporter）に指定できるprovider**

| provider | 呼び出すもの |
| --- | --- |
| RubyLLMのプロバイダ（`gemini`、`anthropic`、`openai`、`openrouter`、`ollama` など） | [RubyLLM](https://rubyllm.com) 経由のAPI。既定は `gemini` の `gemini-3.8-flash` |
| `claude_code` | `claude -p`（サブスクリプション）。ツールをすべて無効にし、空の一時ディレクトリで実行 |
| `codex` | `codex exec`（サブスクリプション）。読み取り専用のサンドボックスで、空の一時ディレクトリで実行 |

レポート役の `provider` は省略でき、その場合はモデル名からプロバイダを決めます。RubyLLMのモデル一覧にない新しいモデルを使うときは、`provider` を指定してください。

diffには外部から来たコードが含まれるため、`claude_code` / `codex` はコマンドを実行できない状態で動かします。サブスクリプションのレート制限を考慮して、CLIを使うときのレポートの並列数は既定で3です（`reporter.concurrency` で変更できます）。

## 設定

プロジェクトルートにある`.omamorirc`ファイルで、Omamoriの動作をカスタマイズできます。

設定項目の詳細は以下の通りです：

```yaml
# .omamorirc
# omamori用設定ファイル

# 判定役（任意）。省略するとレポート役が全項目を判定します。--classifier で上書きできます
# classifier:
#   provider: typesafe      # typesafe / openai / ollama
#   model: jev-1.13.0       # 閾値を調整するなら、jev-latest ではなく版を固定する
#   threshold: 0.3          # この確率以上の項目をレポート役に回す
#   concurrency: 8          # 判定役に同時に投げるリクエスト数
#   base_url: https://api.typesafe.ai   # 任意。SystemOne形式の別のサーバーを使うとき
#   api_key: ...            # 任意。環境変数（TYPESAFE_API_KEY など）を推奨

# レポート役（任意。既定は gemini / gemini-3.8-flash）。--reporter で上書きできます
# reporter:
#   provider: anthropic     # RubyLLMのプロバイダ、または claude_code / codex
#   model: claude-sonnet-5-5
#   concurrency: 8          # レポートを並列で書く数（CLIの既定は3、APIの既定は8）
#   command: /path/to/claude   # 任意。claude_code / codex のCLIのパス
#   api_key: ...            # 任意。環境変数（ANTHROPIC_API_KEY など）を推奨

# 実行するセキュリティチェック（任意。デフォルトは判定役なしで主要8項目、判定役ありで全37項目）
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

- `classifier`: 判定役。`provider`、`model`、`threshold`（デフォルト0.3）、`concurrency`（デフォルト8）、`base_url`、`api_key`。
- `reporter`: レポート役。`provider`、`model`、`concurrency`、`command`、`api_key`。
- `checks`: 実行するセキュリティチェックのリスト。
- `prompt_templates`: AI解析用のカスタムプロンプトテンプレートを設定。
- `report`: レポート出力に関する設定。
  - `output_path`: HTMLおよびJSONレポートの出力先ディレクトリまたはプレフィックス。
  - `html_template`: カスタムHTMLテンプレート（ERB形式）のパス。
- `static_analysers`: 静的解析ツール（Brakeman、Bundler-Auditなど）の追加オプション設定。
- `language`: AI解析結果の詳細説明文の言語設定。デフォルトは英語（`en`）。

以前の書き方（`engine`、`llm`、`model`、`provider`、`api_key`、`decision`、`claude`、`codex`）と、以前のオプション（`--engine`、`--llm`）も、引き続き使えます。

## .omamoriignore ファイル

`.omamoriignore`ファイルを使用すると、特定のファイルやディレクトリをスキャン対象から除外できます。ただし、`--force-scan-ignored`オプションを指定した場合は、このファイルの設定は無視されます。これは`.gitignore`ファイルと似たような働きをしますが、以下の点に注意してください。

*   **有効なモード:** `--all` モード、またはファイル/ディレクトリを指定してスキャンする場合にのみ有効です。
*   **無効なモード:** `diff` モード（引数なしの `omamori scan`、または `--base`）では、`.omamoriignore` ファイルは無視されます。これは、`git diff` で取得された変更点のみを対象とするためです。
*   **書式:** 1行に1つのパターンを記述します。`#` で始まる行はコメントとして扱われます。
    *   末尾が `/` のパターンは、そのディレクトリ以下をすべて除外します（例: `vendor/bundle/`）。
    *   それ以外のパターンは、プロジェクトルートからの相対パスかファイル名に対するglobとして評価されます（例: `*.log`、`spec/fixtures/*.rb`）。

`omamori init` コマンドを実行すると、一般的なRailsプロジェクトで無視すべきファイルやディレクトリのパターンが記述された`.omamoriignore`ファイルが生成されます。必要に応じてこのファイルを編集してください。

## CIで使う

GitHub Actions または GitLab CI の設定ファイルを生成できます：

```bash
omamori ci-setup --ci github_actions   # .github/workflows/omamori_scan.yml
omamori ci-setup --ci gitlab_ci        # .gitlab-ci.yml
```

生成される設定は、プルリクエスト（マージリクエスト）では `--base` でブランチの差分を、それ以外では `--all` でコードベース全体をスキャンします。差分を取るため、リポジトリは履歴ごと取得します。APIキーはCIのシークレット（GitLabではCI/CD変数）に登録してください。判定役を使う場合は、生成された設定のコメントにある `TYPESAFE_API_KEY` などの行を有効にし、`.omamorirc` に `classifier` を設定します。

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

    判定役（Jev）で試す場合：

    ```bash
    omamori scan --classifier typesafe
    ```

    または、ステージ後にすべてのファイルをスキャンする場合：

    ```bash
    omamori scan --all
    ```

## 検出精度の測定

`evals/` には、正解のわかっているコード変更の問題集があります。37項目それぞれについて、脆弱な変更と「惜しいけど安全な」変更を2つずつ、さらに無害な変更を収録しています。XSS、SQLインジェクション、Mass Assignmentには、見逃しやすい具体的な形のケースも追加しています。判定役やレポート役を変えたときに、見逃しと誤検知がどう変わるかを測れます。

```bash
bundle exec ruby evals/run.rb --classifier typesafe --runs 3
bundle exec ruby evals/run.rb --classifier none --reporter claude_code --reporter-model sonnet
```

使い方は [evals/README.md](evals/README.md) を参照してください。

## 貢献について

バグ報告やプルリクエストはGitHubで歓迎しています。このプロジェクトは、安全かつ協力的なコラボレーションの場を目指しています。

## ライセンス

このGemは、[MITライセンス](https://opensource.org/licenses/MIT)のもとでオープンソースとして公開されています。
