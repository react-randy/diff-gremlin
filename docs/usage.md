# Usage

`diff-gremlin --help` lists commands. Each scanning command accepts `--profile`,
`--format`, `--timeout`, `--fail-under`, `--fail-on`, and `--require-complete`.
Run `diff-gremlin doctor` to inspect installed tools and `diff-gremlin policy` to
print the score policy identity and exit semantics.

The comparison improvements below are on main and await the next release. The
published 1.1.0 wheel and image retain their original comparison behavior.

## Check a repository

```sh
diff-gremlin check .
diff-gremlin check /path/to/repo --ref HEAD
diff-gremlin check https://github.com/OWNER/REPO --ref FULL_COMMIT_SHA
```

Local checks without `--ref` snapshot current files, including uncommitted work.
A ref selects a Git object without switching your checkout. Repository URLs must
use supported HTTPS forms. Scans run on disposable snapshots and leave your
branch, index, working tree, and global Git configuration unchanged.

Git snapshots containing submodules (gitlinks) or unsupported object modes are
refused before analysis. To scan explicitly materialized submodule contents, supply
a local directory snapshot without `--ref`; its identity describes current files.
The checker does not initialize submodules or run their hooks.

The default is full. Files outside the bounded source inventory, unreadable
files, omitted stages, unsupported syntax, and missing tools are disclosed in
the report. “No findings” is useful only together with the observed coverage.

## Review a PR or MR

```sh
diff-gremlin pr https://github.com/OWNER/REPO/pull/123
diff-gremlin pr https://gitlab.com/GROUP/REPO/-/merge_requests/123 --profile full
```

The provider supplies immutable base/head SHAs and both repository identities,
including a fork when relevant. Diff Gremlin verifies the fetched objects before
analysis. A review compares those exact snapshots; it does not simulate a merge
or silently replace the base with a merge base. Use `compare` to choose a different
explicit base.

PR/MR mode defaults to quick for the first review pass. Quick visibly omits PyScn
health/clones/dead code, Radon maintainability, JavaScript jscpd clones, and bounded
Python history. Selected lint/type/complexity/security/hygiene checks still run.
Choose full for the broader declared analysis and inspect any remaining limitations.

```sh
diff-gremlin compare . main HEAD
diff-gremlin compare https://github.com/OWNER/REPO BASE_SHA HEAD_SHA --format json
```

Full JSON comparison reports preserve both receipts and stage IDs. An unavailable check cannot
resolve a finding from the other snapshot. Compare profiles and tool versions
before interpreting a numeric change.

## Comparison verdicts

`delta_assessment` describes new or worsened evidence separately from the base and
head snapshot assessments. An unchanged function above CC 50 remains a snapshot
blocker but does not fail the default comparison gate. An existing function that
grows from CC 52 to 61 is a changed observation and a blocking regression, even
when another unchanged function remains the repository maximum. New or worsened
critical findings and other existing blocker thresholds retain their force.

Moved named functions match by stable identity. Changed measurements appear in
`changed_findings` with base/head values. Ambiguous or anonymous observations are
matched conservatively. Limited evidence cannot confirm a resolution or a clean
comparison. Default comparisons exit 0 with complete evidence and no blocking
regression, 1 for a demonstrated blocker regression, or 3 when evidence is
incomplete. Explicit `--fail-on`/`--fail-under` retain head snapshot gate semantics,
including inherited blockers. Repository `check` semantics stay as documented below.

Shell function changes retain the named `shell-ast-decision-complexity-v1`
estimate. The existing above-50 blocker threshold applies to that measure;
it is not labelled as exact cyclomatic complexity.

## Select comparison paths

```sh
diff-gremlin compare . main HEAD --paths app --paths resources
diff-gremlin compare . main HEAD --changed-paths --format json-delta
diff-gremlin pr https://github.com/OWNER/REPO/pull/123 --changed-paths --paths ui
```

`--paths` accepts repeatable literal repository-relative files or subtrees;
absolute paths, parent escapes and Git pathspec magic are rejected. Combining it
with `--changed-paths` selects their intersection. Changed paths come from the
exact supplied snapshots and include deleted and renamed paths on their respective
sides. An empty selection remains empty. These options apply to `compare`/`pr`.

Selection happens before content and selected-file budgets. Tree metadata remains
bounded. Full tree overflow errors report the configured limit and observed count
or lower bound. A selected receipt contains `source_selection` with mode, paths,
per-side tracked total/selected/omitted counts and bounds. These counts precede
ordinary directory and content exclusions. The required `scope.selection` gap
keeps the strict assessment unknown: a selected scan describes partial repository
evidence even when every analyzer completes. Repository history is excluded from
this selected scope. Cross-file imports, clones and global metrics can change
when only a subset is present; selection cannot certify the whole repository.

## Human reports and machine receipts

```sh
diff-gremlin check . --format text
diff-gremlin pr https://github.com/OWNER/REPO/pull/123 --format markdown
diff-gremlin check . --format json > receipt.json
diff-gremlin compare . main HEAD --format json-delta > delta.json
```

Text is the default. Text and Markdown prioritize the top 20 findings and top 10
next actions, with total counts and an explicit note for additional observations.
JSON retains every finding, next action, and source-scope path. Markdown is suitable
for a review artifact. JSON stdout
contains only JSON on successful report creation; operational errors go to stderr
and may produce no receipt. Save the process exit status as well as the document.
One flushed completion line per stage appears on stderr, with base/head labels
for comparisons. `--quiet` suppresses progress. Library scans remain silent unless
given a progress callback.

JSON declares `schema_version`, tool/policy versions, source identity, profile,
coverage, stages, assessment, and limitations. Each stage names its tool/version,
status, analyzed/eligible file counts, located findings, metrics, and limitation
reason. A comparison contains the two scan receipts and their deltas. Consumers
should check schema/profile/coverage and preserve unknown evidence.

Schema 1.2.0 adds comparison delta assessment, changed observations, native
measurement fields on findings, stage base/head reasons, and optional source
selection. `in_changed_lines` is true/false for known coordinates and null when
unavailable. It describes the finding's location, not proof that the diff caused
it. Added observations use head coordinates, resolutions use base coordinates,
and changed findings carry both. `json-delta` omits both full snapshot arrays while
retaining source identities, profile/coverage, snapshot assessment summaries,
delta verdict, stage reasons and changed evidence. Full JSON remains available.

Missing TypeScript dependencies and JSX environment diagnostics are aggregated at
stage level instead of repeated as source findings. The stage remains limited;
other source diagnostics retain bounded sanitized compiler messages. Unsupported
Blade templates and absent dependency semantics still keep strict evidence
incomplete. They cannot be made complete by ignoring the limitation.

Schema 1.1.0 adds `assessment.observed`, a provisional score from validated checks,
including contributing/applicable category weights and partial categories. The
original `assessment.score` remains null unless required evidence is complete;
existing CI gates use that strict field. Ordinary images and binary archives are
listed as outside text analysis in `inventory.metrics.scope_manifest`; omitted
possible source remains a coverage gap. No target dependency installation is needed
to receive the findings that static checks can actually observe.

## CI gates

```sh
diff-gremlin check . --fail-under 80 --fail-on high --require-complete --format json > receipt.json
```

| Status | Process exit |
| --- | --- |
| Complete selected checks with configured gates passed | `0` |
| Known blocker, score below `--fail-under`, or finding at/above `--fail-on` | `1` |
| Usage/acquisition/operation error | `2` |
| Required evidence incomplete | `3` |

`--fail-under` accepts a score from 0 to 100. `--fail-on` accepts `low`, `medium`,
`high`, or `critical`. `--require-complete` makes CI intent visible; incomplete
evidence already exits 3. Known blockers take precedence over incompleteness.
`--timeout SECONDS` sets the acquisition/analyzer deadline, from greater than zero
to at most 3600 seconds (default 120); it is not a whole-command time guarantee.

A complete quick result covers its selected profile. Require full explicitly
when a CI job needs the broader stages: `--profile full --require-complete`.
The [score policy](score-policy.md) explains weights, category aggregation,
unknowns, blockers, and how a complete independently clean control can earn 100.

## Private repositories

Prefer cloning/fetching with your normal trusted provider setup, then check or
compare the local repository. No container credential forwarding is needed for
that workflow.

For provider URLs, the local CLI can use authenticated `gh`/`glab` where available,
or the supported host-scoped token variables for provider metadata and Git access.
Use `GH_TOKEN`/`GITHUB_TOKEN` for github.com. Enterprise GitHub requires the matching
`GH_HOST` plus `GH_ENTERPRISE_TOKEN`/`GITHUB_ENTERPRISE_TOKEN`. GitLab uses the matching
`GITLAB_HOST` plus `GITLAB_TOKEN`/`GLAB_TOKEN`. Never embed a token in the repository URL.
Do not put secrets in reports, command examples, or shared shell histories.

The container does not include provider CLI logins. To authorize private GitHub
URL access explicitly, supply an already-exported token without writing its value
in the command:

```sh
docker run --rm -e GH_TOKEN ghcr.io/react-randy/diff-gremlin:1.1.0 \
  pr https://github.com/OWNER/PRIVATE_REPO/pull/123
```

Analyzer subprocesses receive a minimal environment that excludes provider tokens
and target configuration. No target dependency, build, test, wrapper, lifecycle
script, or plugin runs during a scan. Static tools and source parsers still process
untrusted bytes; use [restricted Docker settings](installation.md#docker) when you
need an operating-system boundary.

## Legacy commands

The installed `vibe-check` alias supports positional checks, `--pr URL`, and
`TARGET --compare BASE HEAD`. See the [migration map](migration.md). New integrations
should use explicit `diff-gremlin` subcommands and the versioned JSON format.
