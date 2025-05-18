# frozen_string_literal: true

require_relative "lib/omamori/version"

Gem::Specification.new do |spec|
  spec.name = "omamori"
  spec.version = Omamori::VERSION
  spec.authors = ["rira100000000"]
  spec.email = ["101010hayakawa@gmail"]

  spec.summary = "AI-powered security vulnerability scanner for Ruby projects."
  spec.description = "omamori scans Ruby code and diffs using AI (Google Gemini) to detect security vulnerabilities often missed by traditional tools."
  spec.homepage = "https://github.com/rira100000000/omamori"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` command returns everything that isn't ignored by git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) ||
        f.match(%r{\A(?:(?:test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Specify your gem's dependencies in omamori.gemspec
  spec.add_dependency "colorize", "~> 0.8" # Add dependency for colorize
  spec.add_dependency "dotenv", "~> 2.0" # Add dependency for dotenv
  spec.add_dependency "ruby-gemini-api", "~> 0.1.1" # Add dependency for Gemini API
  spec.add_dependency "brakeman", "~> 7.0"
  spec.add_dependency "bundler-audit", "~> 0.9.2"
  # Development dependencies
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
end