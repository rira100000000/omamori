[README(日本語)](https://github.com/rira100000000/omamori/blob/main/README_ja.md)
# Omamori Gem

Omamori is a Ruby gem designed to detect potential security vulnerabilities in Ruby code and its dependencies.
It aims to diagnose common vulnerabilities often introduced by beginner programmers.
By combining static analysis tools with AI-powered code analysis, Omamori provides flexible diagnostic capabilities.

However, please note that this gem is merely a "protective charm" and does not guarantee the safety of your programs.
It might help prevent vulnerabilities that could occur even after human review.

Caution:
AI analysis can uncover vulnerabilities that static analysis alone might miss, but LLM results tend to vary from run to run.
The decision model mode (e.g. Jev) checks each of the 35 risks independently, which makes results more stable.


## Features

- Scan staged changes (`git diff --staged`), a branch diff (`--base`), the entire codebase, or specified files and directories for security risks.
- Fast checklist mode: each of 35 vulnerability types is checked as a yes/no question by a decision model (TypeSafe Jev, OpenAI Decisions), and an LLM writes a detailed report only for the checks that are flagged.
- Choose any LLM: an API through RubyLLM (Gemini, Claude, OpenAI, ...) or a Claude Code (`claude -p`) / Codex (`codex exec`) subscription.
- Integrates with static analysis tools like Brakeman and Bundler-Audit.
- Supports multiple report formats (console, HTML, JSON).
- Generates GitHub Actions / GitLab CI configuration.
- An eval set (`evals/`) for measuring detection accuracy.
- Configurable via a `.omamorirc` file.
- Exclusion of files and directories via a `.omamoriignore` file (except in `diff` mode).

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

Edit the generated `.omamorirc` and `.omamoriignore` files to configure the LLM and model, checks to perform, files/directories to exclude from scanning, and other settings.

### API Keys

API keys are passed through environment variables. Set the ones for the features you use:

```bash
export GEMINI_API_KEY=...     # Default LLM (gemini-3.8-flash)
export TYPESAFE_API_KEY=...   # For --engine jev
export OPENAI_API_KEY=...     # For --engine openai
```

To use an LLM other than Gemini, set that provider's environment variable (`ANTHROPIC_API_KEY`, etc.). `--llm claude` / `--llm codex` use the installed CLI's login, so no API key is needed.

### Scanning

The recommended way is to check the branch diff with a decision model:

```bash
omamori scan --base main --engine jev
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

Specify output format (console, html, json):

```bash
bundle exec omamori scan --format html
bundle exec omamori scan --all --format json
```

### Scan Specific Files/Directories

You can specify particular files or directories to scan:

```bash
omamori scan <file_path1> <file_path2> ... <directory_path1> ...
```

Example:

```bash
omamori scan app/controllers/users_controller.rb app/models/user.rb config/routes.rb lib/
```

This mode respects the `.omamoriignore` file.

### AI Analysis Only

To perform only AI analysis without running static analysis tools, use the `--ai` option:

```bash
omamori scan --ai
```

### Fast Checklist Mode (Jev / OpenAI Decisions)

With `--engine jev` or `--engine openai`, each security check runs as an independent yes/no question on a fast decision model.

```bash
omamori scan --base main --engine jev
omamori scan --base main --engine openai
```

1. The diff is split per file. For each file, all checks (35 by default) are sent to the decision model in a single request. Files are processed in parallel.
2. Checks whose probability is below the threshold pass immediately.
3. Only the remaining checks are sent to the LLM, which writes a report following that vulnerability's detection steps.

The questions sent to the decision model contain the same vulnerability definitions and detection steps that the LLM receives. If the decision model fails for a file, every check for that file is escalated to the LLM. If the LLM cannot write a report, the decision model's flag is kept in the results, so nothing is silently skipped.

| engine | Decision model | Decision model API key |
| --- | --- | --- |
| `llm` (default) | None. The LLM checks everything at once | None |
| `jev` | TypeSafe Jev | `TYPESAFE_API_KEY` |
| `openai` | OpenAI Decisions API (`gpt-6-luna`) | `OPENAI_API_KEY` |

With `jev`, you can point `decision.jev.base_url` at any other server that speaks the SystemOne protocol. The old `engine: gemini` still works and means `llm`.

### Choosing the LLM

`--llm` chooses the LLM that writes reports (and, with `--engine llm`, checks everything itself).

```bash
omamori scan --base main --engine jev                # reports by the model set in `model` (default gemini-3.8-flash)
omamori scan --base main --engine jev --llm claude   # reports by claude -p
omamori scan --base main --engine jev --llm codex    # reports by codex exec
omamori scan --llm claude                            # claude -p does everything
```

| llm | What it calls |
| --- | --- |
| `api` (default) | An API through [RubyLLM](https://rubyllm.com), using the model set in `model`. Any provider RubyLLM supports works: Gemini, Anthropic, OpenAI, OpenRouter, Ollama, and more |
| `claude` | `claude -p` (subscription) with all tools disabled, in an empty temporary directory |
| `codex` | `codex exec` (subscription) in a read-only sandbox, in an empty temporary directory |

For `api`, API keys are read from each provider's environment variable (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, ...: RubyLLM's setting name in upper case). Set `provider` too when the model name does not identify the provider, or when the model is not in RubyLLM's model registry. The old `llm: gemini` still works and means `api`.

Diffs contain code from outside sources, so the CLIs run without the ability to execute commands. Because subscriptions have tighter rate limits, reports are written 3 at a time when a CLI is used (change with `decision.report_concurrency`).

You can measure each engine's detection accuracy with the eval set in `evals/` (vulnerable cases and safe near misses for each of the 35 risks, plus benign changes). See [evals/README.md](evals/README.md).

## Configuration

The `.omamorirc` file in the project root directory allows you to customize Omamori's behavior.

```yaml
# .omamorirc
# Configuration file for omamori gem

# AI engine (optional, default: llm). Can be overridden with --engine
# engine: jev

# LLM (optional, default: api). Can be overridden with --llm
# llm: api

# Model used when llm is api (optional, default: gemini-3.8-flash)
# model: claude-sonnet-5-5
# provider: anthropic   # Optional. Set when the model name does not identify the provider

# Gemini API key (optional). The GEMINI_API_KEY environment variable is recommended
# api_key: YOUR_GEMINI_API_KEY

# Settings for llm: claude / codex (optional)
# claude:
#   model: sonnet       # Omit to use the CLI's default model
# codex:
#   model: gpt-5.5      # Omit to use the CLI's default model

# Decision model settings (when engine is jev or openai)
# decision:
#   threshold: 0.3          # Checks at or above this probability are reported by the LLM
#   concurrency: 8          # Parallel requests to the decision model
#   report_concurrency: 3   # Reports written in parallel (default 3 for CLIs, 8 for APIs)
#   jev:
#     model: jev-1.13.0     # Pin a version (not jev-latest) if you tune the threshold
#     base_url: https://api.typesafe.ai
#   openai:
#     model: gpt-6-luna

# Security checks to run (optional; default: the 6 main checks with engine: llm, all 35 with jev / openai)
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

*   `engine`: `llm`, `jev`, or `openai`. Defaults to `llm` (`gemini` means the same).
*   `llm`: `api`, `claude`, or `codex`. Defaults to `api` (`gemini` means the same).
*   `model`: The model used with `llm: api`. Any model RubyLLM supports. Defaults to `gemini-3.8-flash`.
*   `provider`: The RubyLLM provider used with `llm: api` (`gemini`, `anthropic`, `openai`, ...). Optional.
*   `api_key`: Gemini API key. Passing it via the `GEMINI_API_KEY` environment variable is recommended. Keys for other providers are passed via environment variables.
*   `claude` / `codex`: `model` and `command` (path to the CLI) when using a CLI.
*   `decision`: Decision model settings: `threshold` (default 0.3), `concurrency` (default 8), `report_concurrency`, and per-engine `model`, `base_url`, `api_key`. Passing API keys via the `TYPESAFE_API_KEY` and `OPENAI_API_KEY` environment variables is recommended.
*   `checks`: The list of security checks to run.
*   `prompt_templates`: Define custom prompt templates for AI analysis.
*   `report`: Configure report output settings.
    *   `output_path`: The output directory or prefix for HTML and JSON reports.
    *   `html_template`: Path to a custom ERB template for HTML reports.
*   `static_analysers`: Configure options for integrated static analysis tools.
    *   `brakeman`: Additional command-line options for Brakeman.
    *   `bundler_audit`: Additional command-line options for Bundler-Audit.
*   `language`: Language setting for the details provided in AI analysis reports. Defaults to English (`en`).

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

The generated configuration scans the branch diff with `--base` on pull requests (merge requests) and the entire codebase with `--all` otherwise. It fetches the full history so the diff can be taken. Register API keys as CI secrets (CI/CD variables on GitLab). To use a decision model, uncomment the `TYPESAFE_API_KEY` (or similar) line in the generated configuration and set `engine: jev` in `.omamorirc`.

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
    To try a decision model:
    ```bash
    omamori scan --engine jev
    ```
    Or to scan all files in the demo directory (after staging them):
    ```bash
    omamori scan --all
    ```

## Contributing

Bug reports and pull requests are welcome on GitHub. This project is intended to be a safe, welcoming space for collaboration. 

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
