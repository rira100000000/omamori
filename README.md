[README(日本語)](https://github.com/rira100000000/omamori/blob/main/README_ja.md)
# Omamori Gem

Omamori is a Ruby gem designed to detect potential security vulnerabilities in Ruby code and its dependencies.
It aims to diagnose common vulnerabilities often introduced by beginner programmers.
By combining static analysis tools with AI-powered code analysis, Omamori provides flexible diagnostic capabilities.

However, please note that this gem is merely a "protective charm" and does not guarantee the safety of your programs.
It might help prevent vulnerabilities that could occur even after human review.

Caution:
AI analysis can uncover vulnerabilities that static analysis alone might miss, but LLM results tend to vary from run to run.
With a classifier, each of the 37 risks is checked independently, which makes results more stable.

## Features

- Scan staged changes (`git diff --staged`), a branch diff (`--base`), the entire codebase, or specified files and directories.
- Fast checklist: each of 37 vulnerability types is checked as a yes/no question by a decision model (TypeSafe Jev, OpenAI Decisions, ...), and an LLM writes a detailed report only for the flagged checks.
- Choose the classifier and the reporter independently. The reporter can be any API RubyLLM supports (Gemini, Claude, OpenAI, ...) or a Claude Code (`claude -p`) / Codex (`codex exec`) subscription.
- Integrates with static analysis tools like Brakeman and Bundler-Audit.
- Supports multiple report formats (console, HTML, JSON).
- Generates GitHub Actions / GitLab CI configuration.
- An eval set (`evals/`) for measuring detection accuracy.
- Configuration via a `.omamorirc` file, and exclusions via a `.omamoriignore` file.

## How It Works

Omamori's AI analysis has two roles.

- **Classifier:** A fast decision model that checks each of the 37 risks as a yes/no question, such as TypeSafe Jev or OpenAI Decisions. Optional.
- **Reporter:** The LLM that writes vulnerability reports. Without a classifier, the reporter checks every risk itself in one prompt.

With a classifier, a scan works like this:

1. The diff is split per file. For each file, all checks (37 by default) are sent to the classifier in a single request. Files are processed in parallel.
2. Checks whose probability is below the threshold pass immediately.
3. Only the remaining checks are sent to the reporter, which writes a report following that vulnerability's detection steps.

The questions sent to the classifier contain the same vulnerability definitions and detection steps that the reporter receives. For XSS, SQL injection, mass assignment, CSRF, and open redirect, the classifier also answers sub-checks: concrete patterns that alone make the risk real (for XSS, for example, "is a URL from users put into `href` without checking its scheme?"). The highest probability among the overall question and its sub-checks is used, and the matched sub-checks are passed on to the reporter. If the classifier fails for a file, every check for that file is escalated to the reporter. If the reporter cannot write a report, the classifier's flag is kept in the results, so nothing is silently skipped.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omamori'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install omamori
```

## Usage

### Initialization

To generate an initial configuration file (`.omamorirc`), run:

```bash
omamori init
```

Edit the generated `.omamorirc` and `.omamoriignore` files to configure the classifier and reporter, checks to perform, files/directories to exclude from scanning, and other settings.

### API Keys

API keys are passed through environment variables. Set the ones for the features you use:

```bash
export GEMINI_API_KEY=...     # Default reporter (gemini-3.8-flash)
export TYPESAFE_API_KEY=...   # Classifier: typesafe (Jev)
export OPENAI_API_KEY=...     # Classifier: openai
```

For a reporter other than Gemini, set that provider's environment variable (`ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, ...: RubyLLM's setting name in upper case). The `claude_code` / `codex` reporters use the installed CLI's login, so no API key is needed.

### Scanning

The recommended way is to check the branch diff with a classifier (Jev):

```bash
omamori scan --base main --classifier typesafe
```

Scan staged changes (default):

```bash
omamori scan
```

Scan the changes on the current branch (`main...HEAD`, i.e. what a pull request contains; useful in CI):

```bash
omamori scan --base main
```

Scan the entire codebase:

```bash
omamori scan --all
```
This mode respects the `.omamoriignore` file.

Scan specific files or directories:

```bash
omamori scan app/controllers/users_controller.rb app/models/user.rb config/routes.rb lib/
```
This mode also respects the `.omamoriignore` file.

Specify the output format (console, html, json):

```bash
omamori scan --format html
omamori scan --all --format json
```

Run only AI analysis, skipping static analysis tools:

```bash
omamori scan --ai
```

### Choosing the Classifier and Reporter

Both roles are set with a `provider` and a `model`, on the command line or in `.omamorirc` (see [Configuration](#configuration)).

```bash
omamori scan --base main --classifier typesafe                           # Jev decides, Gemini reports
omamori scan --base main --classifier typesafe --reporter claude_code    # Jev decides, claude -p reports
omamori scan --base main --classifier openai --reporter anthropic --reporter-model claude-sonnet-5-5
omamori scan --reporter codex                                            # No classifier; codex exec checks everything
```

**Classifier providers**

| provider | Decision model | API key |
| --- | --- | --- |
| `typesafe` | TypeSafe Jev (`jev-1.13.0` when `model` is omitted) | `TYPESAFE_API_KEY` |
| `openai` | OpenAI Decisions API (`gpt-6-luna` when `model` is omitted) | `OPENAI_API_KEY` |
| `ollama` | A decision model running on Ollama (such as Clef). `model` and the server's `base_url` (or `OLLAMA_API_BASE`) are required | None |
| `none` | No classifier (default) | None |

With `base_url`, you can point a classifier at any other server that speaks the SystemOne protocol.

**Reporter providers**

| provider | What it calls |
| --- | --- |
| A RubyLLM provider (`gemini`, `anthropic`, `openai`, `openrouter`, `ollama`, ...) | An API through [RubyLLM](https://rubyllm.com). Defaults to `gemini` with `gemini-3.8-flash` |
| `claude_code` | `claude -p` (subscription) with all tools disabled, in an empty temporary directory |
| `codex` | `codex exec` (subscription) in a read-only sandbox, in an empty temporary directory |

The reporter's `provider` can be omitted, in which case it is inferred from the model name. Set `provider` when the model is too new to be in RubyLLM's model registry.

A reporter may refuse to analyze some content (Gemini sometimes refuses security analysis). A refused check is not silently passed; the classifier's flag is kept. With a fallback reporter (`reporter.fallback`), refused or failed checks are asked again there, and only those.

```bash
omamori scan --base main --classifier typesafe --reporter-fallback claude_code --reporter-fallback-model sonnet
```

Diffs contain code from outside sources, so `claude_code` / `codex` run without the ability to execute commands. Because subscriptions have tighter rate limits, reports are written 3 at a time when a CLI is used (change with `reporter.concurrency`).

## Configuration

The `.omamorirc` file in the project root directory allows you to customize Omamori's behavior.

```yaml
# .omamorirc
# Configuration file for omamori gem

# Classifier (optional). Without it, the reporter checks every risk. Can be overridden with --classifier
# classifier:
#   provider: typesafe      # typesafe / openai / ollama
#   model: jev-1.13.0       # Pin a version (not jev-latest) if you tune the threshold
#   threshold: 0.3          # Checks at or above this probability go to the reporter
#   concurrency: 8          # Parallel requests to the classifier
#   base_url: https://api.typesafe.ai   # Optional. Another SystemOne server
#   api_key: ...            # Optional. Environment variables (TYPESAFE_API_KEY, ...) are recommended

# Reporter (optional; default: gemini / gemini-3.8-flash). Can be overridden with --reporter
# reporter:
#   provider: anthropic     # A RubyLLM provider, or claude_code / codex
#   model: claude-sonnet-5-5
#   concurrency: 8          # Reports written in parallel (default 3 for CLIs, 8 for APIs)
#   command: /path/to/claude   # Optional. Path to the claude_code / codex CLI
#   api_key: ...            # Optional. Environment variables (ANTHROPIC_API_KEY, ...) are recommended
#   fallback:               # Optional. Asked only when the reporter refuses or fails
#     provider: claude_code
#     model: sonnet

# Security checks to run (optional; default: the 8 main checks without a classifier, all 37 with one)
# checks:
#   - xss
#   - csrf
#   - idor

# Custom prompt templates (optional)
# prompt_templates:
#   default: |
#     Your custom prompt template here...

# Report output settings (optional)
# report:
#   output_path: ./omamori_report # Output directory/prefix for html/json reports
#   html_template: path/to/custom/template.erb # Custom HTML template

# Static analyser options (optional)
# static_analysers:
#   brakeman:
#     options: "--force" # Additional Brakeman options
#   bundler_audit:
#     options: "--quiet" # Additional Bundler-Audit options

# Language setting for AI analysis details (optional, default: en)
# language: ja
```

*   `classifier`: `provider`, `model`, `threshold` (default 0.3), `concurrency` (default 8), `base_url`, `api_key`.
*   `reporter`: `provider`, `model`, `concurrency`, `command`, `api_key`, `fallback` (a fallback reporter with its own `provider`, `model`, ...).
*   `checks`: The list of security checks to run.
*   `prompt_templates`: Define custom prompt templates for AI analysis.
*   `report`: Configure report output settings.
    *   `output_path`: The output directory or prefix for HTML and JSON reports.
    *   `html_template`: Path to a custom ERB template for HTML reports.
*   `static_analysers`: Configure options for integrated static analysis tools.
    *   `brakeman`: Additional command-line options for Brakeman.
    *   `bundler_audit`: Additional command-line options for Bundler-Audit.
*   `language`: Language setting for the details provided in AI analysis reports. Defaults to English (`en`).

The older keys (`engine`, `llm`, `model`, `provider`, `api_key`, `decision`, `claude`, `codex`) and options (`--engine`, `--llm`) still work.

## .omamoriignore File

The `.omamoriignore` file allows you to exclude specific files and directories from the scan target. However, if the `--force-scan-ignored` option is used, the settings in this file will be ignored. Its behavior is similar to a `.gitignore` file, but with the following considerations:

*   **Effective Modes:** It is only effective in `--all` mode or when scanning specified files/directories.
*   **Ineffective Mode:** In `diff` mode (i.e., `omamori scan` without arguments, or with `--base`), the `.omamoriignore` file is ignored. This is because `diff` mode only targets changes retrieved by `git diff`.
*   **Format:** Each line specifies one pattern. Lines starting with `#` are treated as comments.
    *   A pattern ending with `/` excludes everything under that directory (e.g., `vendor/bundle/`).
    *   Other patterns are evaluated as globs against the path relative to the project root or the file name (e.g., `*.log`, `spec/fixtures/*.rb`).

When you run the `omamori init` command, a `.omamoriignore` file pre-filled with patterns for common files and directories to ignore in a Rails project will be generated. You can edit this file as needed.

## Using in CI

You can generate GitHub Actions or GitLab CI configuration:

```bash
omamori ci-setup --ci github_actions   # .github/workflows/omamori_scan.yml
omamori ci-setup --ci gitlab_ci        # .gitlab-ci.yml
```

The generated configuration scans the branch diff with `--base` on pull requests (merge requests) and the entire codebase with `--all` otherwise. It fetches the full history so the diff can be taken. Register API keys as CI secrets (CI/CD variables on GitLab). To use a classifier, uncomment the `TYPESAFE_API_KEY` (or similar) line in the generated configuration and set `classifier` in `.omamorirc`.

## Demo Files

The `demo` directory contains example files with known vulnerabilities that can be used to demonstrate Omamori's capabilities.

To run Omamori on the demo files, you need to stage the changes in the `demo` directory. Since the `demo` directory might be ignored by git, follow these steps:

1.  Copy the `demo` directory:
    ```bash
    cp -r demo demo_
    ```
2.  Stage the `demo_` directory:
    ```bash
    git add demo_
    ```
3.  Now you can run Omamori on the staged demo files:
    ```bash
    omamori scan
    ```
    To try a classifier (Jev):
    ```bash
    omamori scan --classifier typesafe
    ```
    Or to scan all files in the demo directory (after staging them):
    ```bash
    omamori scan --all
    ```

## Measuring Detection Accuracy

`evals/` contains code changes with known answers. For each of the 37 risks there are two vulnerable changes and two "near miss" changes that look similar but are safe, plus a set of benign changes. XSS, SQL injection, mass assignment, IDOR, CSRF, and open redirect also have cases for specific patterns that are easy to miss. Use it to see how misses and false positives change when you switch the classifier or reporter.

```bash
bundle exec ruby evals/run.rb --classifier typesafe --runs 3
bundle exec ruby evals/run.rb --classifier none --reporter claude_code --reporter-model sonnet
```

See [evals/README.md](evals/README.md) for details.

## Contributing

Bug reports and pull requests are welcome on GitHub. This project is intended to be a safe, welcoming space for collaboration. 

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
