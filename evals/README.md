# omamori evals

A set of code changes with known answers, used to check how well each engine detects each security risk from a diff.

## Running

```bash
bundle exec ruby evals/run.rb --runs 3                                  # classifier: typesafe (Jev)
bundle exec ruby evals/run.rb --classifier openai --runs 3              # classifier: OpenAI Decisions
bundle exec ruby evals/run.rb --classifier none                         # baseline: Gemini checks all risks in one prompt
bundle exec ruby evals/run.rb --classifier none --reporter claude_code --reporter-model sonnet   # same baseline with claude -p
bundle exec ruby evals/run.rb --risk xss                                # only cases for one risk
bundle exec ruby evals/run.rb --risk xss --no-sub-checks                # overall questions only, without sub-checks
bundle exec ruby evals/run.rb --risk xss --pipeline --threshold 0.5     # also run the reporter on flagged checks
bundle exec ruby evals/run.rb --case safe-url-attribute --pipeline      # one case, to trace what happens
```

By default only the classifier is scored: a case's answer is the classifier's probability, and the table shows recall and specificity at each threshold. With `--pipeline`, every labeled check the classifier flags at `--threshold` is also sent to the reporter, as `omamori scan` does, and the case's answer becomes the reporter's verdict. This is the accuracy a user actually sees. When the reporter cannot answer (for example Gemini refusing the content), the check stays flagged; those are counted separately as "unanswered".

`evals/holdout/` is a separate validation set, written without looking at `evals/cases/` or the sub-checks. Tune questions and sub-checks on `evals/cases/` only, and run `--holdout` to check that the improvement carries over to cases the tuning never saw. Do not edit sub-checks to fix holdout mistakes; add those shapes to `evals/cases/` instead, and write fresh holdout cases later.

```bash
bundle exec ruby evals/run.rb --holdout --pipeline --threshold 0.5
```

## Real security fixes

`evals/real/` measures the tool on real vulnerabilities instead of written cases. `collect.rb` gathers security-fix commits from the GitHub Advisory Database (rubygems ecosystem) into `manifest.yml`. Each fix gives two cases: the fix applied in reverse (introduces the vulnerability, expected true) and the fix itself (touches the same code safely, expected false).

Only references are stored. The code is fetched with the `gh` CLI when the evals run and cached in `evals/.cache/` (not committed), because those projects have their own licenses.

```bash
ruby evals/real/collect.rb                                    # rebuild the manifest (slow; needs gh)
bundle exec ruby evals/run.rb --real --split tune             # the half used for tuning
bundle exec ruby evals/run.rb --real --split holdout --pipeline --threshold 0.5
bundle exec ruby evals/run.rb --real --kind app               # application code only (or library)
```

Labels from advisories are noisy. `review.yml` records a manual review of the cases the pipeline got wrong; cases found mislabeled or unusable are left out of scoring (`--no-review` keeps them).

## Cost

Only the questions for the labeled risks are sent (`--all-risks` sends every risk), and classifier answers are cached in `evals/.cache/judge/` by model, code, and questions, so a rerun of the same cases costs nothing. The cache is turned off automatically with `--runs 2` or more, and `--no-cache` turns it off explicitly.

Results also keep every question's probability for the labeled risks (`questions` in the JSON), so you can see which sub-checks fire on which cases.

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
