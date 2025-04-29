# Omamori Gem

Omamori is a Ruby gem that helps identify potential security vulnerabilities in your Ruby code and dependencies using a combination of static analysis tools and AI-powered code analysis.

## Features

- Scan staged changes (`git diff --staged`) or the entire codebase for security risks.
- Integrates with static analysis tools like Brakeman and Bundler-Audit.
- Utilizes the Gemini API for advanced code analysis to detect vulnerabilities.
- Supports multiple report formats (console, HTML, JSON).
- Can generate basic CI/CD setup files for GitHub Actions and GitLab CI.
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

### CI/CD Setup

Generate a GitHub Actions workflow file (`.github/workflows/omamori_scan.yml`):

```bash
omamori ci-setup github_actions
```

Generate a GitLab CI configuration file (`.gitlab-ci.yml`):

```bash
omamori ci-setup gitlab_ci
```

Remember to add your `GEMINI_API_KEY` as a secret variable in your CI/CD settings.

## Configuration

The `.omamorirc` file in the project root directory allows you to customize Omamori's behavior.

Here's a detailed breakdown of the configuration options:

```yaml
# .omamorirc
# Configuration file for omamori gem

# Gemini API Key (required for AI analysis)
# You can also set this via the GEMINI_API_KEY environment variable
api_key: YOUR_GEMINI_API_KEY # Replace with your actual API key

# Gemini Model to use (optional, default: gemini-1.5-pro-latest)
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
*   `model`: The Gemini model to use for AI analysis. Defaults to `gemini-1.5-pro-latest`.
*   `checks`: Configure which types of security checks to enable. By default, all implemented checks are enabled. You can selectively enable/disable checks here (e.g., `xss: true`, `csrf: false`).
*   `prompt_templates`: Define custom prompt templates for AI analysis.
*   `report`: Configure report output settings.
    *   `output_path`: The output directory or prefix for HTML and JSON reports.
    *   `html_template`: Path to a custom ERB template for HTML reports.
*   `static_analysers`: Configure options for integrated static analysis tools.
    *   `brakeman`: Additional command-line options for Brakeman.
    *   `bundler_audit`: Additional command-line options for Bundler-Audit.
*   `language`: Language setting for the details provided in AI analysis reports. Defaults to English (`en`).

## Contributing

Bug reports and pull requests are welcome on GitHub. This project is intended to be a safe, welcoming space for collaboration. 

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Demo Files

The `demo` directory contains example files with known vulnerabilities that can be used to demonstrate Omamori's capabilities.

To run Omamori on the demo files, you need to stage the changes in the `demo` directory. Since the `demo` directory might be ignored by git, follow these steps:

1.  Ensure the `demo` directory is not ignored by git. If it is listed in your `.gitignore` file, remove or comment out the line.
2.  Remove the `demo` directory from the git cache:
    ```bash
    git rm -r --cached demo
    ```
3.  Stage the `demo` directory again:
    ```bash
    git add demo
    ```
4.  Now you can run Omamori on the staged demo files:
    ```bash
    omamori scan
    ```
    Or to scan all files in the demo directory (after staging them):
    ```bash
    omamori scan --all
    ```