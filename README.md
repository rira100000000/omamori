[README(日本語)](https://github.com/rira100000000/omamori/blob/main/README_ja.md)
# Omamori Gem

Omamori is a Ruby gem designed to detect potential security vulnerabilities in Ruby code and its dependencies.
It aims to diagnose common vulnerabilities often introduced by beginner programmers.
By combining static analysis tools with AI-powered code analysis, Omamori provides flexible diagnostic capabilities.

However, please note that this gem is merely a "protective charm" and does not guarantee the safety of your programs.
It might help prevent vulnerabilities that could occur even after human review.

Caution:
AI analysis can uncover vulnerabilities that static analysis alone might miss, but the accuracy of diagnostics may vary depending on the AI model’s "mood."
Running the analysis multiple times may help reduce false negatives.


## Features

- Scan staged changes (`git diff --staged`) or the entire codebase for security risks.
- Integrates with static analysis tools like Brakeman and Bundler-Audit.
- Utilizes the Gemini API for advanced code analysis to detect vulnerabilities.
- Supports multiple report formats (console, HTML, JSON).
- Configurable via a `.omamorirc` file.

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

Edit the generated `.omamorirc` file to configure your Gemini API key, preferred model, checks to perform, and other settings.

### Scanning

Scan staged changes (default):

```bash
omamori scan
```

Scan the entire codebase:

```bash
omamori scan --all
```

Specify output format (console, html, json):

```bash
bundle exec omamori scan --format html
bundle exec omamori scan --all --format json
```

### AI Analysis Only

To perform only AI analysis without running static analysis tools, use the `--ai` option:

```bash
omamori scan --ai
```

## Configuration

The `.omamorirc` file in the project root directory allows you to customize Omamori's behavior.

Here's a detailed breakdown of the configuration options:

```yaml
# .omamorirc
# Configuration file for omamori gem

# Gemini API Key (required for AI analysis)
# You can also set this via the GEMINI_API_KEY environment variable
api_key: YOUR_GEMINI_API_KEY # Replace with your actual API key

# Gemini Model to use (optional, default: gemini-2.5-flash-preview-04-17)
model: gemini-2.5-flash-preview-04-17

# Security checks to enable (optional, default: all implemented checks)
# checks:
#   xss: true
#   csrf: true
#   idor: true
#   ... # Add other checks as they become available

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

*   `api_key`: Your API key for accessing the Gemini API. Can also be set via the `GEMINI_API_KEY` environment variable.
*   `model`: The Gemini model to use for AI analysis. Defaults to `gemini-2.5-flash-preview-04-17`.
*   `checks`: Configure which types of security checks to enable. By default, all implemented checks are enabled. You can selectively enable/disable checks here (e.g., `xss: true`, `csrf: false`).
*   `prompt_templates`: Define custom prompt templates for AI analysis.
*   `report`: Configure report output settings.
    *   `output_path`: The output directory or prefix for HTML and JSON reports.
    *   `html_template`: Path to a custom ERB template for HTML reports.
*   `static_analysers`: Configure options for integrated static analysis tools.
    *   `brakeman`: Additional command-line options for Brakeman.
    *   `bundler_audit`: Additional command-line options for Bundler-Audit.
*   `language`: Language setting for the details provided in AI analysis reports. Defaults to English (`en`).

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
    Or to scan all files in the demo directory (after staging them):
    ```bash
    omamori scan --all
    ```

## Contributing

Bug reports and pull requests are welcome on GitHub. This project is intended to be a safe, welcoming space for collaboration. 

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
