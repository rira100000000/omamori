# frozen_string_literal: true

# Collects real security fixes from the GitHub Advisory Database (rubygems ecosystem) and writes
# evals/real/manifest.yml. Only references are stored; the code is fetched at eval time.
#
#   ruby evals/real/collect.rb            # needs the gh CLI, logged in
#   ruby evals/real/collect.rb --refilter # only re-apply the filters below to the existing manifest
#
# Each selected fix becomes two cases: the fix reversed (introduces the vulnerability, expected true)
# and the fix itself (a near miss that touches the same code, expected false).

require 'json'
require 'yaml'
require 'open3'

CWE_TO_RISK = {
  79 => 'xss', 89 => 'sql_injection', 918 => 'ssrf', 78 => 'dangerous_eval', 77 => 'dangerous_eval',
  22 => 'directory_traversal', 601 => 'open_redirect', 352 => 'csrf', 639 => 'idor', 915 => 'mass_assignment'
}.freeze
CODE_FILE = /\.(rb|erb|haml|slim|js|jsx|ts|tsx|rake)\z/
IGNORED_PATH = %r{(\A|/)(spec|test|tests|__tests__|fixtures|vendor|dist|locales?)/|_spec\.rb\z|_test\.rb\z|\.min\.js\z}
MAX_FILES = 3
MAX_CHANGED_LINES = 80
MANIFEST = File.expand_path('manifest.yml', __dir__)
# Files that only bump a version are not a fix
VERSION_ONLY = %r{(\A|/)version\.rb\z}
# Application code (as opposed to library internals), to report the two separately
APP_PATH = %r{(\A|/)app/(controllers|models|views|helpers|services|jobs|uploaders|packs|javascript)/}

# Drops backports and duplicate advisories of the same change, and version-only commits.
def finalize(entries)
  entries
    .reject { |e| e['files'].all? { |f| f.match?(VERSION_ONLY) } }
    .map { |e| e.merge('files' => e['files'].grep_v(VERSION_ONLY), 'kind' => e['files'].any? { |f| f.match?(APP_PATH) } ? 'app' : 'library') }
    .uniq { |e| [e['risk'], e['repo'], e['files'].sort] }
    .sort_by { |e| [e['risk'], e['id']] }
end

if ARGV.include?('--refilter')
  entries = finalize(YAML.safe_load_file(MANIFEST).fetch('entries'))
  File.write(MANIFEST, { 'entries' => entries }.to_yaml)
  puts "#{entries.size} fixes kept in #{MANIFEST}"
  exit
end

def gh(*args)
  out, status = Open3.capture2('gh', 'api', *args)
  status.success? ? JSON.parse(out) : nil
end

# The advisories API pages with cursors, so let gh follow the Link headers
def advisories(cwe)
  out, status = Open3.capture2('gh', 'api', '--paginate', '--jq', '.[]',
                               "/advisories?ecosystem=rubygems&cwes=#{cwe}&per_page=100")
  status.success? ? out.lines.map { |line| JSON.parse(line) } : []
end

def commit_refs(advisory)
  Array(advisory['references']).filter_map { |url| url[%r{github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})}] && [$1, $2] }.uniq
end

# Release commits that only change a VERSION constant (it may live in the main file, e.g. lib/rubygems.rb)
def version_bump_only?(files)
  changed_lines = files.flat_map { |file| file['patch'].to_s.lines.grep(/\A[+-](?![+-])/) }
  changed_lines.any? && changed_lines.all? { |line| line.match?(/\A[+-]\s*VERSION\s*=/) }
end

def select_fix(repo, sha)
  commit = gh("/repos/#{repo}/commits/#{sha}")
  return nil unless commit && commit['parents']&.size == 1

  files = Array(commit['files']).select do |file|
    file['filename'].match?(CODE_FILE) && !file['filename'].match?(IGNORED_PATH) && file['status'] == 'modified'
  end
  changed = files.sum { |file| file['additions'] + file['deletions'] }
  return nil if files.empty? || files.size > MAX_FILES || changed > MAX_CHANGED_LINES
  return nil if version_bump_only?(files)

  { 'sha' => commit['sha'], 'parent' => commit['parents'].first['sha'], 'files' => files.map { |f| f['filename'] } }
end

entries = []
CWE_TO_RISK.each do |cwe, risk|
  advisories(cwe).each do |advisory|
    commit_refs(advisory).each do |repo, sha|
      fix = select_fix(repo, sha)
      next unless fix

      entries << {
        'id' => "#{risk}-#{advisory['ghsa_id'].downcase}-#{fix['sha'][0, 7]}",
        'risk' => risk,
        'cwe' => "CWE-#{cwe}",
        'advisory' => advisory['ghsa_id'],
        'summary' => advisory['summary'],
        'repo' => repo,
        'commit' => fix['sha'],
        'parent' => fix['parent'],
        'files' => fix['files']
      }
      warn "#{entries.last['id']} #{repo} #{fix['files'].join(', ')}"
    end
  end
end

entries = finalize(entries)
File.write(MANIFEST, { 'entries' => entries }.to_yaml)
puts "#{entries.size} fixes written to #{MANIFEST}"
