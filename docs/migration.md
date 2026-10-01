# From vibe-check to Diff Gremlin

The inherited implementation remains in Git history at commit
`170bd72b96546a8f206ce907d807e61447df1535`. Its MIT attribution remains in LICENSE.
The 2,059-line script is replaced by an installable package and a compatibility
entry point. `vibe-check` remains a console alias. Private Python helper functions
from the old script are not a supported API.

| Inherited feature/test family | Current boundary | Deliberate change |
| --- | --- | --- |
| Grades, CC, MI, auto-F | policy and calibration tests | A truly clean control can earn 100; missing evidence is unknown; MI is informational. |
| Language/hygiene helpers | inventory and hygiene tests | Empty test directories do not count as a suite; all exclusions are visible. |
| PyScn health/duplication | Python adapters and native/schema controls | One fresh stdout JSON; real zero remains distinct from missing/malformed output. |
| Hidden Unicode/execution | contextual security tests | Actual syntax and located findings; safe subprocess calls are informational. |
| Java semantics | Java parser and standalone types controls | No target Maven/Gradle/wrapper execution; unresolved dependencies are limited. |
| TypeScript dependency preparation | controlled compiler tests | No target npm install, lifecycle scripts, plugins or project configs. |
| GitHub/GitLab URLs and refs | provider and acquisition tests | Fork-aware immutable SHAs; exact base/head comparison is disclosed. |
| Comparison arrows, flags, hotspots | reporting delta tests | Both full receipts, stable stage IDs, unknown coverage never resolves a finding. |
| Clone/temp/auth helpers | process and acquisition tests | Owned snapshots, ephemeral credentials, bounded execution, no global Git changes. |
| CLI parsing/full scan | CLI and integration tests | Discoverable subcommands, JSON, meaningful gates and exit codes. |

The old tests exercised the monolith's private helpers and some unsafe behavior
as the expected outcome. They are replaced by the mapped behavioral suites;
their original versions remain in history. Regression controls now prove that
timeouts cannot score clean, malicious wrappers cannot execute, and caller
checkouts remain unchanged.

Supported legacy commands:

```sh
vibe-check .
vibe-check --pr https://github.com/OWNER/REPO/pull/123
vibe-check . --compare main HEAD
```

Use `diff-gremlin --help` for the current interface. Script execution requires an
installed package; running a checkout directly uses `uv run diff-gremlin`.
