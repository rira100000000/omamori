# omamori evals

A set of code changes with known answers, used to check how well each engine detects each security risk from a diff.

## Running

```bash
bundle exec ruby evals/run.rb --runs 3                                  # classifier: typesafe (Jev)
bundle exec ruby evals/run.rb --classifier openai --runs 3              # classifier: OpenAI Decisions
bundle exec ruby evals/run.rb --classifier none                         # baseline: Gemini checks all risks in one prompt
bundle exec ruby evals/run.rb --classifier none --reporter claude_code --reporter-model sonnet   # same baseline with claude -p
bundle exec ruby evals/run.rb --risk xss                                # only cases for one risk
```

For each case, the runner creates a throwaway git repository, commits the `before` files, writes the `after` files, and takes `git diff`. The diff then goes through the same path as `omamori scan`: split per file, every risk asked for each file. A case's probability for a risk is the highest probability among its files.

Results are written to `evals/results/` (not committed).

## Case format

One YAML file per case in `evals/cases/<risk>/`.

```yaml
id: xss-vulnerable-raw-in-view
description: Renders a user-supplied bio with raw, bypassing escaping
expected:
  xss: true          # this change introduces the risk
files:
  - path: app/views/users/show.html.erb
    before: |        # omit for a new file
      <p><%= @user.bio %></p>
    after: |
      <p><%= raw @user.bio %></p>
```

- `expected` lists only the risks the case is about. Risks not listed are not scored for that case (a vulnerable XSS change may reasonably also trigger a CSP check).
- Benign cases in `evals/cases/benign/` list every risk as `false`. They measure false positives on ordinary changes.
- Each risk has a vulnerable case and a safe "near miss": a change that touches the same kind of code but does it correctly. The near miss is what tells a classifier that only matches keywords apart from one that understands the code.
- Secrets in cases are obviously fake and do not use real provider prefixes.
