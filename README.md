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
bundle exec omamori init
```

Edit the generated `.omamorirc` file to configure your Gemini API key, preferred model, checks to perform, and other settings.

### Scanning

Scan staged changes (default):

```bash
bundle exec omamori scan
```

Scan the entire codebase:

```bash
bundle exec omamori scan --all
```

Specify output format (console, html, json):

```bash
bundle exec omamori scan --format html
bundle exec omamori scan --all --format json
```

### CI/CD Setup

Generate a GitHub Actions workflow file (`.github/workflows/omamori_scan.yml`):

```bash
bundle exec omamori ci-setup github_actions
```

Generate a GitLab CI configuration file (`.gitlab-ci.yml`):

```bash
bundle exec omamori ci-setup gitlab_ci
```

Remember to add your `GEMINI_API_KEY` as a secret variable in your CI/CD settings.

## Configuration

The `.omamorirc` file in the project root directory allows you to customize Omamori's behavior.

```yaml
# .omamorirc
# Configuration file for omamori gem

# Gemini API Key (required for AI analysis)
# You can also set this via the GEMINI_API_KEY environment variable
api_key: YOUR_GEMINI_API_KEY # Replace with your actual API key

# Gemini Model to use (optional, default: gemini-1.5-pro-latest)
# model: gemini-1.5-flash-latest

# Security checks to enable (optional, default: all implemented checks)
# checks:
#   - xss
#   - csrf
#   - idor
#   ...

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

# CI setup output paths (optional)
# ci_setup:
#   github_actions_path: .github/workflows/omamori_scan.yml
#   gitlab_ci_path: .gitlab-ci.yml
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the tagged commit, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at [link to your repo]. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org/version/2/0/) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Omamori project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [Code of Conduct](http://contributor-covenant.org/version/2/0/).