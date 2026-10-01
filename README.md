# Diff Gremlin

**Catch rough edges before merge.** Static risk checks for a repo or pull request,
with findings, coverage, and JSON receipts. No model, API key, or AI-authorship guess.

## Install

The v1.0.0 installer and container commands below require the published release.
During release preparation, use the [source installation](docs/installation.md#from-source).

```sh
curl -fsSL https://github.com/react-randy/diff-gremlin/releases/download/v1.0.0/install.sh | sh
diff-gremlin doctor
```

The installer verifies the release wheel and dependency hashes, uses an isolated
uv tool environment, and adds Gitleaks. Python full checks include PyScn where its
platform wheel is available. It does not install Node or Java. See [platform support,
manual installation, and uninstall](docs/installation.md).

**Full toolchain, one command:** Python, TypeScript/JavaScript, Java, and secrets.

```sh
docker run --rm ghcr.io/react-randy/diff-gremlin:1.0.0 pr https://github.com/OWNER/REPO/pull/123
```

For local code, mount the repo read-only:

```sh
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --network=none --tmpfs /tmp:rw,nosuid,nodev,size=1g \
  --mount "type=bind,src=$PWD,dst=/workspace,readonly" \
  ghcr.io/react-randy/diff-gremlin:1.0.0 check /workspace
```

## Review a change

```sh
diff-gremlin pr https://github.com/OWNER/REPO/pull/123
diff-gremlin pr https://gitlab.com/GROUP/REPO/-/merge_requests/123 --profile full
diff-gremlin compare . main HEAD --format markdown
```

PR/MR checks default to **quick**: PyScn health/clones/dead code, maintainability,
JavaScript clones, and history are visibly omitted. Repo checks default to **full**.
Quick results describe their selected checks. They are not a full assessment.
Reviews compare exact pinned provider base/head commits; this is not a simulated merge.

Read added findings, changed signals, and coverage before deciding what to review
or fix. Removed findings are only reported as resolved when both relevant checks
completed. [Usage and private repositories →](docs/usage.md)

## Evaluate a repository

```sh
diff-gremlin check https://github.com/OWNER/REPO
diff-gremlin check . --ref HEAD
diff-gremlin check . --format json > receipt.json
```

A local check reads current files, including uncommitted work. `--ref` selects a
Git snapshot. The receipt records source identity, profile, policy version, tools,
findings, and missing evidence. Share the receipt alongside your adoption review;
then inspect dependencies, tests, and project ownership yourself.

## Make CI decisions explicit

```sh
diff-gremlin check . --fail-under 80 --fail-on high --require-complete --format json > receipt.json
```

| Exit | Meaning |
| --- | --- |
| `0` | Complete selected evidence; configured gates passed |
| `1` | Known blocker or configured gate failed |
| `2` | Usage, acquisition, or operational error |
| `3` | Required evidence incomplete |

A missing, failed, limited, unsupported, skipped, or timed-out required check makes
the headline score **unknown**. It cannot become a passing number. Known blockers
remain visible. Scores use a [versioned policy](docs/score-policy.md), with independent
clean and deliberately bad controls. A score is an observation, not a security or
correctness certificate. It cannot tell you who wrote the code.

## What gets checked

Python uses Ruff, Pyrefly, Lizard, Radon, and optional PyScn. JavaScript/TypeScript
uses ESLint, TypeScript, Lizard, and jscpd. Java uses JDK parser/type controls and
Lizard. Gitleaks and contextual source checks provide located security findings;
repository hygiene and bounded Python Git history add context. Mixed repositories
retain separate analyzer identities. [Exact tools and limits →](docs/toolchain.md)

Scanning reads disposable snapshots. It never runs target builds, tests, wrappers,
plugins, lifecycle scripts, or dependency installation. Local uv environments
isolate dependencies; they are not an operating-system sandbox. Use the restricted
Docker invocation above for an additional boundary. External imports and unsupported
syntax can limit static type evidence; the report says so.

[Install](docs/installation.md) · [Usage](docs/usage.md) ·
[Develop](docs/development.md) · [Architecture](docs/architecture.md) ·
[Migration](docs/migration.md)

MIT. Derived from [nexus-marbell/vibe-check](https://github.com/nexus-marbell/vibe-check/tree/170bd72b96546a8f206ce907d807e61447df1535);
original Marbell AG attribution is preserved in [LICENSE](LICENSE).
