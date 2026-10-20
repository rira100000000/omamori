# frozen_string_literal: true

# Collects ordinary (not security-related) commits from open-source Rails applications and writes
# evals/real/ordinary.yml. They are used to measure how often omamori raises an alarm on a normal change.
# Only references are stored; the code is fetched at eval time.
#
#   ruby evals/real/collect_ordinary.rb [per_repo]   # needs the gh CLI, logged in

require 'json'
require 'yaml'
require 'open3'

REPOS = %w[mastodon/mastodon discourse/discourse decidim/decidim solidusio/solidus chatwoot/chatwoot
           forem/forem opf/openproject zammad/zammad].freeze
PER_REPO = (ARGV.first || 13).to_i
CODE_FILE = /\.(rb|erb|haml|slim|js|jsx|ts|tsx|rake)\z/
IGNORED_PATH = %r{(\A|/)(spec|test|tests|__tests__|fixtures|vendor|dist|locales?|db/migrate)/|_spec\.rb\z|_test\.rb\z|\.min\.js\z}
SECURITY_WORDS = /secur|vulnerab|xss|csrf|inject|traversal|ssrf|cve|ghsa|sanitiz|escap|exploit|attack|permission|authoriz|authent|leak|bypass|unsafe/i
# GitHub's message when a fix from a private security-advisory fork is merged
ADVISORY_MERGE = /\AMerge commit from fork/
MAX_FILES = 3
MAX_CHANGED_LINES = 80
OUTPUT = File.expand_path('ordinary.yml', __dir__)

def gh(path)
  out, status = Open3.capture2('gh', 'api', path)
  status.success? ? JSON.parse(out) : nil
end

def ordinary_commit(repo, summary)
  return nil if summary['parents'].size != 1
  return nil if summary.dig('commit', 'message').match?(SECURITY_WORDS)
  return nil if summary.dig('commit', 'message').match?(ADVISORY_MERGE)
  return nil if summary.dig('author', 'type') == 'Bot' || summary.dig('commit', 'author', 'name').to_s.match?(/bot\b|\[bot\]|dependabot|renovate/i)

  commit = gh("/repos/#{repo}/commits/#{summary['sha']}")
  return nil unless commit

  files = Array(commit['files']).select do |file|
    file['filename'].match?(CODE_FILE) && !file['filename'].match?(IGNORED_PATH) && file['status'] == 'modified'
  end
  changed = files.sum { |file| file['additions'] + file['deletions'] }
  return nil if files.empty? || files.size > MAX_FILES || changed > MAX_CHANGED_LINES

  {
    'id' => "ordinary-#{repo.split('/').last}-#{commit['sha'][0, 7]}",
    'repo' => repo,
    'commit' => commit['sha'],
    'parent' => commit['parents'].first['sha'],
    'message' => commit.dig('commit', 'message').lines.first.strip,
    'files' => files.map { |f| f['filename'] }
  }
end

entries = REPOS.flat_map do |repo|
  picked = []
  page = 1
  while picked.size < PER_REPO && page <= 5
    Array(gh("/repos/#{repo}/commits?per_page=100&page=#{page}")).each do |summary|
      break if picked.size >= PER_REPO

      entry = ordinary_commit(repo, summary)
      picked << entry if entry
    end
    page += 1
  end
  warn "#{repo}: #{picked.size}"
  picked
end

File.write(OUTPUT, { 'entries' => entries }.to_yaml)
puts "#{entries.size} ordinary commits written to #{OUTPUT}"
