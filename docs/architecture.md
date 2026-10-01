# Architecture

Diff Gremlin separates source acquisition, observations, policy, and presentation.
An analyzer reports facts. Policy interprets those facts. Reports show the result.

| Directory | Responsibility |
| --- | --- |
| `domain/` | Define the evidence exchanged between capabilities. |
| `acquisition/` | Produce disposable source snapshots. |
| `providers/` | Resolve immutable review identities. |
| `analyzers/` | Produce evidence from a specific installed tool or static check. |
| `policy/` | Interpret evidence under a versioned decision policy. |
| `reporting/` | Present the same evidence to humans and agents. |

## Adapter contract

An adapter accepts `ScanContext` and returns `StageResult` (or a list when one
validated tool invocation provides several capabilities). IDs identify a
capability; labels serve readers. Mixed-language capabilities keep distinct IDs.

- `ok`: execution and output were validated. Findings may still exist.
- `limited`: only part of the declared scope was examined.
- `missing`, `failed`, `timeout`, `unsupported`, `skipped`: no passing evidence.

Each result names its tool/version, scope, eligible/analyzed files, metrics,
located findings, and a reason for any limitation. Health, maintainability, and
history remain visible without counting the same fact twice in the score.

`RunResult.status == "ok"` means a process completed. Adapters still validate
their allowed exit codes and output schema. A lint tool's findings exit differs
from a configuration failure.

## Source boundary

Acquisition yields context-managed `Snapshot` or `SnapshotPair` values. Analysis
reads the owned snapshot. It does not switch the caller's branch, install project
dependencies, invoke target wrappers, or write global Git configuration.

Provider metadata records both repositories and full expected SHAs. Acquisition
verifies those objects. Reports distinguish the provider base from the chosen
comparison base and never silently follow a moving branch.

Analyzer location validation builds `SourceLocations` once per observation batch.
Its canonical inventory belongs to that batch; each incoming path is resolved
again and must map to an inventoried file. No global cache crosses snapshots.
Lizard validates per-file function counts with one histogram, and Python declaration
reconciliation receives only the observations for that file. This keeps inventory
validation linear in files plus observations while preserving missing-evidence checks.

## Contribution rule

Give each function one operation and each file one responsibility. Add a new
adapter beside existing adapters, using the shared evidence contract. A failure
fixture belongs with that adapter. Share behavior through imports rather than
copies or instructions to keep two implementations in sync.
