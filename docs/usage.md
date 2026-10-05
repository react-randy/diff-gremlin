# Usage

`diff-gremlin --help` lists commands. Each scanning command accepts `--profile`,
`--format`, `--timeout`, `--fail-under`, `--fail-on`, and `--require-complete`.
Run `diff-gremlin doctor` to inspect installed tools and `diff-gremlin policy` to
print the score policy identity and exit semantics.

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

Delta reports preserve both receipts and stage IDs. An unavailable check cannot
resolve a finding from the other snapshot. Compare profiles and tool versions
before interpreting a numeric change.

## Human reports and machine receipts

```sh
diff-gremlin check . --format text
diff-gremlin pr https://github.com/OWNER/REPO/pull/123 --format markdown
diff-gremlin check . --format json > receipt.json
```

Text is the default. Text and Markdown prioritize the top 20 findings and top 10
next actions, with total counts and an explicit note for additional observations.
JSON retains every finding, next action, and source-scope path. Markdown is suitable
for a review artifact. JSON stdout
contains only JSON on successful report creation; operational errors go to stderr
and may produce no receipt. Save the process exit status as well as the document.

JSON declares `schema_version`, tool/policy versions, source identity, profile,
coverage, stages, assessment, and limitations. Each stage names its tool/version,
status, analyzed/eligible file counts, located findings, metrics, and limitation
reason. A comparison contains the two scan receipts and their deltas. Consumers
should check schema/profile/coverage and preserve unknown evidence.

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
