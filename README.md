[README(日本語)](https://github.com/rira100000000/omamori/blob/main/README_ja.md)
# Omamori Gem

Omamori is a Ruby gem designed to detect potential security vulnerabilities in Ruby code and its dependencies.
It aims to diagnose common vulnerabilities often introduced by beginner programmers.
By combining static analysis tools with AI-powered code analysis, Omamori provides flexible diagnostic capabilities.

However, please note that this gem is merely a "protective charm" and does not guarantee the safety of your programs.
It might help prevent vulnerabilities that could occur even after human review.

Caution:
AI analysis can uncover vulnerabilities that static analysis alone might miss, but LLM results tend to vary from run to run.
With a classifier, each of the 35 risks is checked independently, which makes results more stable.

## Features

- Scan staged changes (`git diff --staged`), a branch diff (`--base`), the entire codebase, or specified files and directories.
- Fast checklist: each of 35 vulnerability types is checked as a yes/no question by a decision model (TypeSafe Jev, OpenAI Decisions, ...), and an LLM writes a detailed report only for the flagged checks.
- Choose the classifier and the reporter independently. The reporter can be any API RubyLLM supports (Gemini, Claude, OpenAI, ...) or a Claude Code (`claude -p`) / Codex (`codex exec`) subscription.
- Integrates with static analysis tools like Brakeman and Bundler-Audit.
- Supports multiple report formats (console, HTML, JSON).
- `omamori init` runs with flags only and `omamori doctor` checks the setup, so an AI agent can set omamori up for you.
- Generates GitHub Actions / GitLab CI configuration.
- An eval set (`evals/`) for measuring detection accuracy.
- Configuration via a `.omamorirc` file, and exclusions via a `.omamoriignore` file.

## How It Works

Omamori's AI analysis has two roles.

- **Classifier:** A fast decision model that checks each of the 35 risks as a yes/no question, such as TypeSafe Jev or OpenAI Decisions. Optional.
- **Reporter:** The LLM that writes vulnerability reports. Without a classifier, the reporter checks every risk itself in one prompt.

With a classifier, a scan works like this:

1. The diff is split per file. For each file, all checks (35 by default) are sent to the classifier in a single request. Files are processed in parallel.
2. Checks whose probability is below the threshold pass immediately.
3. Only the remaining checks are sent to the reporter, which writes a report following that vulnerability's detection steps.

The questions sent to the classifier contain the same vulnerability definitions and detection steps that the reporter receives. For XSS, SQL injection, mass assignment, CSRF, open redirect, missing audit logging, insufficient encryption, and insecure deserialization, the classifier also answers sub-checks: concrete patterns that alone make the risk real (for XSS, for example, "is a URL from users put into `href` without checking its scheme?"). The highest probability among the overall question and its sub-checks is used, and the matched sub-checks are passed on to the reporter.

Risks about something being absent (CSP and other security headers, production settings, two-factor authentication, password policy, audit logging) are judged as "does this change weaken or remove an existing protection?". Whether the application had the protection in the first place cannot be told from a diff that does not touch it. If the classifier fails for a file, every check for that file is escalated to the reporter. If the reporter cannot write a report, the classifier's flag is kept in the results, so nothing is silently skipped.

## Getting Started

1. Add omamori to your Gemfile and install it.

    ```ruby
    gem 'omamori', group: :development, require: false
    ```

    ```bash
    bundle install
    ```

2. Choose a reporter and write the config file. The provider and model are given as flags (there are no interactive questions).

    ```bash
    bundle exec omamori init --reporter claude_code                                   # Claude Code subscription (claude -p)
    bundle exec omamori init --reporter codex                                         # Codex subscription (codex exec)
    bundle exec omamori init --reporter anthropic --reporter-model claude-sonnet-5-5  # Any API RubyLLM supports
    ```

    Add `--classifier typesafe` to use a classifier, `--language ja` for reports in Japanese, and `--ci github_actions` (or `gitlab_ci`) to also generate a CI configuration. This writes `.omamorirc` and `.omamoriignore`, then prints the next steps (such as the environment variables to set). An existing `.omamorirc` is not overwritten unless you pass `--force`.

3. Set the environment variables it printed, and check the setup.

    ```bash
    bundle exec omamori doctor
    ```

    This sends the classifier and the reporter one small request each, and says what is missing (an API key, or installing or logging in to a CLI) and how to fix it. It exits with 0 when everything works and 1 otherwise.

4. Scan.

    ```bash
    bundle exec omamori scan --base main
    ```

There is no default reporter. If neither `.omamorirc` nor `--reporter` sets one, `omamori scan` stops and shows how to run `init`.

### API Keys

API keys are passed through environment variables, named after RubyLLM's settings in upper case (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `TYPESAFE_API_KEY` for the Jev classifier, ...). `omamori init` prints the ones your setup uses. The `claude_code` / `codex` reporters use the installed CLI's login, so no API key is needed.

Code diffs are sent to the classifier and reporter providers you choose. For code that must not leave your environment, choose a model that runs locally, such as one on Ollama.

## Setting Up with an AI Agent

When you ask an AI coding agent (Claude Code, Codex, ...) to set up omamori, it can follow these steps:

1. Add `gem 'omamori', group: :development, require: false` to the Gemfile and run `bundle install`
2. Choose the reporter: `claude_code` if the `claude` command exists, `codex` if `codex` exists. Otherwise, ask the developer which API provider and model they use
3. Ask the developer whether to use a classifier (`--classifier typesafe`, ...). It makes scans faster and more stable, but needs that provider's API key and sends the code to that provider as well
4. Run `bundle exec omamori init --reporter ... [--reporter-model ...] [--classifier ...] [--language ja] [--ci github_actions]`
5. Ask the developer to set the environment variables it printed. Do not ask them to paste API keys into the chat, and do not write keys into files
6. Run `bundle exec omamori doctor`, fixing what it reports, until it exits with 0
7. Run `bundle exec omamori scan --base main` and report the results. If a CI configuration was generated, also tell the developer the secret names to register (printed by `init`)

## Usage

### Scanning

Any setting in `.omamorirc` can be changed for one run with flags (see Choosing the Classifier and Reporter).

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
omamori scan --base main --classifier typesafe --reporter gemini --reporter-model gemini-3.8-flash   # Jev decides, Gemini reports
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
| A RubyLLM provider (`gemini`, `anthropic`, `openai`, `openrouter`, `ollama`, ...) | An API through [RubyLLM](https://rubyllm.com). `model` is required |
| `claude_code` | `claude -p` (subscription) with all tools disabled, in an empty temporary directory |
| `codex` | `codex exec` (subscription) in a read-only sandbox, in an empty temporary directory |

In `.omamorirc`, the reporter's `provider` can be omitted, in which case it is inferred from the model name. Set `provider` when the model is too new to be in RubyLLM's model registry.

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
#   threshold: 0.5          # Checks at or above this probability go to the reporter
#   concurrency: 8          # Parallel requests to the classifier
#   base_url: https://api.typesafe.ai   # Optional. Another SystemOne server
#   api_key: ...            # Optional. Environment variables (TYPESAFE_API_KEY, ...) are recommended

# Reporter (required; written by omamori init). Can be overridden with --reporter
reporter:
  provider: anthropic       # A RubyLLM provider, or claude_code / codex
  model: claude-sonnet-5-5  # Required for API providers. For CLIs, omit it to use the CLI's default model
  # concurrency: 8           # Reports written in parallel (default 3 for CLIs, 8 for APIs)
  # command: /path/to/claude # Optional. Path to the claude_code / codex CLI
  # api_key: ...             # Optional. Environment variables (ANTHROPIC_API_KEY, ...) are recommended
  # fallback:                # Optional. Asked only when the reporter refuses or fails
  #   provider: claude_code
  #   model: sonnet

# Security checks to run (optional; default: the 8 main checks without a classifier, all 35 with one)
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

*   `classifier`: `provider`, `model`, `threshold` (default 0.5), `concurrency` (default 8), `base_url`, `api_key`.
*   `reporter`: `provider`, `model`, `concurrency`, `command`, `api_key`, `fallback` (a fallback reporter with its own `provider`, `model`, ...).
*   `checks`: The list of security checks to run. The former `server_error_information_exposure` is merged into `overly_detailed_errors`. `dependency_trojan_package` (malicious packages) is no longer judged by AI, because it cannot be judged reliably from code: use bundler-audit (run by omamori) for known vulnerable versions, and a scanner with a malicious-package database, such as OSV-Scanner or GitHub dependency review.
*   `prompt_templates`: Define custom prompt templates for AI analysis.
*   `report`: Configure report output settings.
    *   `output_path`: The output directory or prefix for HTML and JSON reports.
    *   `html_template`: Path to a custom ERB template for HTML reports.
*   `static_analysers`: Configure options for integrated static analysis tools.
    *   `brakeman`: Additional command-line options for Brakeman.
    *   `bundler_audit`: Additional command-line options for Bundler-Audit.
*   `language`: Language setting for the details provided in AI analysis reports. Defaults to English (`en`).

The older keys (`engine`, `llm`, `model`, `provider`, `api_key`, `decision`, `claude`, `codex`) and options (`--engine`, `--llm`) still work. A 0.1 config that only sets `api_key` keeps using Gemini (`gemini-3.8-flash`).

## .omamoriignore File

The `.omamoriignore` file allows you to exclude specific files and directories from the scan target. However, if the `--force-scan-ignored` option is used, the settings in this file will be ignored. Its behavior is similar to a `.gitignore` file, but with the following considerations:

*   **Effective Modes:** It is only effective in `--all` mode or when scanning specified files/directories.
*   **Ineffective Mode:** In `diff` mode (i.e., `omamori scan` without arguments, or with `--base`), the `.omamoriignore` file is ignored. This is because `diff` mode only targets changes retrieved by `git diff`.
*   **Format:** Each line specifies one pattern. Lines starting with `#` are treated as comments.
    *   A pattern ending with `/` excludes everything under that directory (e.g., `vendor/bundle/`).
    *   Other patterns are evaluated as globs against the path relative to the project root or the file name (e.g., `*.log`, `spec/fixtures/*.rb`).

When you run the `omamori init` command, a `.omamoriignore` file pre-filled with patterns for common files and directories to ignore in a Rails project will be generated. You can edit this file as needed.

## Using in CI

Pass `--ci` to `omamori init`, or generate the configuration later from `.omamorirc`:

```bash
omamori ci-setup --ci github_actions   # .github/workflows/omamori_scan.yml
omamori ci-setup --ci gitlab_ci        # .gitlab-ci.yml
```

The generated configuration scans the branch diff with `--base` on pull requests (merge requests) and the entire codebase with `--all` otherwise. It fetches the full history so the diff can be taken. It passes the environment variables your classifier and reporter need, and prints the names of the secrets (CI/CD variables on GitLab) to register.

`claude_code` / `codex` use the CLI's login on the machine. The generated configuration does not install or log in a CLI on the CI runner: in CI, add `--reporter PROVIDER --reporter-model MODEL` to the scan command to use an API reporter, or set up the runner yourself.

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
3.  Now you can run Omamori on the staged demo files (set it up with `omamori init --reporter ...` first):
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

`evals/` contains code changes with known answers. For each of the 35 risks there are two vulnerable changes and two "near miss" changes that look similar but are safe, plus a set of benign changes. XSS, SQL injection, mass assignment, IDOR, CSRF, and open redirect also have cases for specific patterns that are easy to miss. Use it to see how misses and false positives change when you switch the classifier or reporter.

```bash
bundle exec ruby evals/run.rb --classifier typesafe --runs 3
bundle exec ruby evals/run.rb --classifier none --reporter claude_code --reporter-model sonnet
```

See [evals/README.md](evals/README.md) for details.

## Contributing

Bug reports and pull requests are welcome on GitHub. This project is intended to be a safe, welcoming space for collaboration. 

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
