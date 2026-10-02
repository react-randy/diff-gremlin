# Field validation

The gremlin went outside. Some receipts were incomplete. That is useful evidence too.

## Method

On 2026-10-01 we selected four public repositories using a Luna research worker,
then scanned immutable commits with the actual full static toolchain. Two came
from GitHub Trending; Java used explicit popularity/recency searches because the
available Java Trending snapshot was stale. This is a small, deliberately varied
sample, not a random population or a quality leaderboard.

Checks used Diff Gremlin 1.0.0, score policy 1.0.0 and the full profile. Analyzer
versions were Ruff 0.16.8, Pyrefly 1.3.0, Lizard 1.24.0, Radon 6.0.1, PyScn
1.32.1, ESLint 10.11.0, TypeScript 6.0.3, jscpd 4.2.3, JDK 25.0.4.1,
Gitleaks 8.30.1 and shfmt 3.14.1; Node 22.23.1 and Python 3.12.3 supplied the
local runtime. These field timings describe this machine and include acquisition.
They are not cross-machine benchmarks.

Only trusted checker tools and shipped parsers ran. Target dependencies, builds,
tests, wrappers, hooks, plugins and package scripts did not run. A static scan does
not establish project runtime correctness, security, license validity or authorship.
Private receipts were checked against the selected source commits. The table
contains sanitized observations; matched credential values and host paths are omitted.

## Pinned sample

| Repository | Immutable source | Selection evidence |
| --- | --- | --- |
| [TwitchDropsMiner](https://github.com/DevilXD/TwitchDropsMiner) | [`22d0c6134f9291d1e904012c465504a22bd3f97c`](https://github.com/DevilXD/TwitchDropsMiner/tree/22d0c6134f9291d1e904012c465504a22bd3f97c) | [Daily Trending, English view](https://github.com/trending?spoken_language_code=en), retrieved Oct 1 |
| [mobile-mcp](https://github.com/mobile-next/mobile-mcp) | [`ef371e8c6fd7fee066d773b98a0ce6b57a73b42d`](https://github.com/mobile-next/mobile-mcp/tree/ef371e8c6fd7fee066d773b98a0ce6b57a73b42d) | [TypeScript Trending](https://github.com/trending?l=TypeScript), returned Sep 29 snapshot; live repository metadata checked Oct 1 |
| [Recipe Lab](https://github.com/voxivoid/recipe-lab-sony-pmca) | [`f488094eed32f59ad23a17bae6d07c7424ef71a4`](https://github.com/voxivoid/recipe-lab-sony-pmca/tree/f488094eed32f59ad23a17bae6d07c7424ef71a4) | Official repository search: Java, created Jul 1–Oct 1, at least 50 stars, public/nonfork/nonarchived; sorted by stars |
| [TheAlgorithms/Java](https://github.com/TheAlgorithms/Java) | [`1c22ba66beac87f731fcb507bfa194db369ed854`](https://github.com/TheAlgorithms/Java/tree/1c22ba66beac87f731fcb507bfa194db369ed854) | Official repository search: Java, at least 50 stars, pushed since Sep 24, GitHub size under 20,000 KiB; sorted by stars |

Trending pages change; those dates describe the research snapshot, not today's
ranking. The Java searches are popularity/recency filters, not Trending rankings.
The sample favors small, active public GitHub repositories in supported languages.

## Results

TwitchDropsMiner completed in **12.04 seconds**, exit **1**, with a **Hold**
decision and **unknown score**: **9/12 required stages** completed. Its `_run`
function at [twitch.py:608](https://github.com/DevilXD/TwitchDropsMiner/blob/22d0c6134f9291d1e904012c465504a22bd3f97c/twitch.py#L608)
had cyclomatic complexity **62**, a configured blocker. Python external imports
limited type evidence, and six binary/large files were omitted from text security
checks. Shallow Git history was an optional limitation. No checker defect was
established by this sample.

mobile-mcp completed the corrected scan in **16.389 seconds**, exit **3**, with
an **unknown score**, **5/9 required stages** complete and no configured blockers.
There were 61 lint findings and 351 function/code-path observations, with maximum
complexity 17. Four binary images were omitted from text security checks; external
type dependencies/globals remained unresolved. Native clone evidence was rejected
with the precise cause: `clone range outside source lines`. The native 1,000-line
filter also excludes its 1,252-line server file; that gap remains visible. A
telemetry credential-pattern match has unknown privileges and is not proof of an
exposed private credential. No matched value is published here.

Twitch used checker commit
[`a68e57934f635bca9a3f8c93af5f8e6a6e82fde2`](https://github.com/react-randy/diff-gremlin/commit/a68e57934f635bca9a3f8c93af5f8e6a6e82fde2).
Mobile's corrected scan used
[`4a3c3f240e910acca2f424aac61cadd78c02da83`](https://github.com/react-randy/diff-gremlin/commit/4a3c3f240e910acca2f424aac61cadd78c02da83).
The original Mobile run was 15.699 seconds with the same score, coverage and
findings; only the useful failure explanation changed. These successive checker
commits share score policy 1.0.0; runtime timing differences are not a claimed speedup.

Recipe Lab exited **2** after **1.704 seconds**, before analysis. The pinned tree
contains the [`jni/platform` submodule](https://github.com/voxivoid/recipe-lab-sony-pmca/tree/f488094eed32f59ad23a17bae6d07c7424ef71a4/jni)
(mode 160000). Acquisition correctly refused a source tree with a gitlink. It
produced **no receipt, score or stage counts**. We retained this refusal in the
sample and selected the fourth Java repository to exercise the parser.

TheAlgorithms/Java completed the corrected scan in **34.984 seconds**, exit **3**,
with an **unknown score**, **11/12 required stages** complete and no configured
blockers. Checker commit
[`8980c4045bbb9f53f92d14c6dd1060b546f93558`](https://github.com/react-randy/diff-gremlin/commit/8980c4045bbb9f53f92d14c6dd1060b546f93558)
produced the receipt. Its sole required gap was standalone Java type evidence:
40 diagnostics included six external-dependency diagnostics. The pinned
[`UnitConversions.java`](https://github.com/TheAlgorithms/Java/blob/1c22ba66beac87f731fcb507bfa194db369ed854/src/main/java/com/thealgorithms/conversions/UnitConversions.java#L6)
imports Apache Commons, which its Maven descriptor declares; the checker does not
install that dependency or run Maven.

Lizard covered 842 production files (841 Java plus one Python) and observed 4,164
functions, maximum complexity **29**. A separate trusted JDK parse-only control
confirmed that complexity at
[`Edmonds.java:84`](https://github.com/TheAlgorithms/Java/blob/1c22ba66beac87f731fcb507bfa194db369ed854/src/main/java/com/thealgorithms/graph/Edmonds.java#L84):
nine for loops, one while, fourteen conditionals and four conditional AND operators,
plus baseline one. This is a review signal, not a configured blocker. Source
security checks covered all 1,669 inventoried files. The small Python slice also
completed its static checks; shallow Python history remained optional and limited.
The aborted 299.807-second baseline never completed, so the two runs do not define
a valid whole-command speedup ratio. No further checker defect was established.

## Stage coverage

Counts are analyzed/eligible files, not a percentage of project behavior tested.
“Limited” retains useful observations while preventing a complete headline score.

| Stage | TwitchDropsMiner | mobile-mcp, corrected |
| --- | --- | --- |
| Inventory / hygiene | Both ok, 57/57 | Both ok, 68/68 |
| Unicode / secrets | Both limited, 51/57 | Both limited, 64/68 |
| Execution observations | Ok, 16/16 | Ok, 32/32 |
| Lizard complexity | Ok, 14/14 | Not selected for JS/TS |
| Ruff | Ok, 14/14 | Not selected |
| Pyrefly | Limited, 14/14 | Not selected |
| PyScn health / clones / dead code | All ok, 14/14; health optional | Not selected |
| Radon maintainability | Ok, 14/14; optional | Not selected |
| Shell syntax / complexity | Both ok, 2/2 | Not selected |
| JS/TS complexity / ESLint | Not selected | Both ok, 18/18 |
| jscpd clones | Not selected | Failed, 0/18 |
| TypeScript | Not selected | Limited, 16/16 |
| Python history | Limited, 14/14; optional | Unsupported, 0/0; optional |

Recipe Lab never reached these stages. The corrected Algorithms receipt contains:

| Stage | Status | Analyzed/eligible |
| --- | --- | --- |
| Inventory / hygiene | Both ok | 1,669/1,669 each |
| Unicode / secrets | Both ok | 1,669/1,669 each |
| Execution observations | Ok | 1,630/1,630 |
| Lizard complexity | Ok | 842/842 |
| Ruff / Pyrefly | Both ok | 1/1 each |
| PyScn health / clones / dead code | All ok; health optional | 1/1 each |
| Radon maintainability | Ok; optional | 1/1 |
| Java syntax structure | Ok | 841/841 |
| Java standalone types | Limited | 841/841 |
| Python history | Limited; optional | 1/1 |

## Fixes discovered in the field

- [#42: Explain rejected native clone evidence](https://github.com/react-randy/diff-gremlin/issues/42).
  mobile-mcp exposed reversed endpoints in native jscpd 4.2.3 output: one simulator
  clone reported lines 207 → 186 and token positions 1841 → 1767. Rejecting this
  evidence was correct. The improvement names the safe validation cause while
  retaining a failed stage, zero credited files and an unknown overall score.
  Invalid clones are not reordered or silently dropped to manufacture a score.
- [#43: Scale inventory-backed validation](https://github.com/react-randy/diff-gremlin/issues/43).
  The first Algorithms scan was explicitly stopped after **299.807 seconds**,
  without a receipt. Independent controls proved that 256 source lookups caused
  **65,792 filesystem resolutions**: the entire allowlist was rebuilt per row.
  The correction constructs source identity once per batch and counts Lizard
  function rows once. The aborted run has no score or completed-stage claim.

## Reproduce

Use the complete Docker toolchain from a supported Linux amd64/arm64 host.
These recorded samples used checker 1.0.0; the reproduction command uses patch
1.0.1, which fixes image publication URLs without changing analyzer logic, versions
or score policy:

```sh
docker run --rm ghcr.io/react-randy/diff-gremlin:1.0.1 check \
  https://github.com/DevilXD/TwitchDropsMiner \
  --ref 22d0c6134f9291d1e904012c465504a22bd3f97c --profile full --format json
```

Replace the URL and full commit with any table entry. Save the exit status along
with the JSON. Acquisition errors may produce no JSON; incomplete evidence must
remain unknown. Machine, runtime, network and analyzer-version differences can
change timing and diagnostics. External dependencies are intentionally not installed.

## Larger mixed repositories: Hindsight, OpenShell and OpenRig

The user selected these three projects for a real adoption check on October 1–2,
2026. Each was acquired directly from its GitHub URL at an immutable commit,
using the full profile and the same trusted native toolchain. Target code and
dependencies remained inert. These are engineering fixtures, not a leaderboard.

| Repository | Immutable source | First integrated URL receipt | Located review signal |
| --- | --- | --- | --- |
| [Hindsight](https://github.com/vectorize-io/hindsight) | `0be6c02b2aafc2b6bdb188ef1842ac507e0cfa2b` | 423.50 s; exit 1; provisional 20/F; 7/16 required complete | `extract_chinese_period`, complexity 315; frontend functions reach 106 |
| [OpenShell](https://github.com/NVIDIA/OpenShell) | `76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2` | 149.14 s; exit 1; provisional 20/F; 9/16 required complete | `handle_forward_proxy`, complexity 142; an e2e cleanup function reaches 64 |
| [OpenRig](https://github.com/mvschwarz/openrig) | `71506f6ed980371342fd99372f32247483d247cc` | 364.54 s; exit 1; provisional 20/F; 10/16 required complete | TUI render code path, complexity 251; `compose_up`, complexity 68 |

Those first integrated receipts used development commit `ed2d563` (package
version 1.0.2, policy/schema 1.1.0). They exposed additional native duplication
and history problems; their coverage and timings are baseline receipts, not
claims about the final released checker. All three had real functions above
the configured complexity blocker of 50, so their observed scores were capped
at 20. Their strict complete scores remained unknown. A complexity signal
identifies review work; it does not establish project correctness, inactivity,
or whether the entire project should be abandoned.

The original v1.0.1 Hindsight URL acquisition refused its 30 MB generator JAR.
The repaired classifier declares recognized binary assets outside text scope
and continues source analysis, without expanding archives. A real NUL-containing
TSX file remains an explicit possible-source gap. Safe symlinks and unavailable
external type dependencies also remain explicit limitations. No target path was
manually removed to make a URL scan pass.

### Defects fixed for 1.0.2

- [#47](https://github.com/react-randy/diff-gremlin/issues/47): mixed source/assets
  and local/ref/provider scope parity. Excluded vendor/build content no longer
  consumes the source read budget; path, mode and symlink validation remains.
- [#48](https://github.com/react-randy/diff-gremlin/issues/48): bounded native
  batching for 11 MB Ruff and 4.8 MB Lizard output, valid negative unused NCSS
  telemetry, larger Python source and native Shell escaped-newline coordinates.
- [#49](https://github.com/react-randy/diff-gremlin/issues/49): located JS/TS
  diagnostics no longer exhaust a 4 MiB aggregate source-reading budget. Captured
  sizes, per-file limits, UTF-16 positions and corruption controls remain.
- [#50](https://github.com/react-randy/diff-gremlin/issues/50): native overlapping
  clone incidences and embedded CSS maps, retained valid clone findings when the
  native detector emits corrupt second endpoints, independent Python dead-code
  evidence, and bounded immutable history beyond 500 Python files.

Native repaired clone probes covered Hindsight 542/572 selected production
JS/TS files, OpenShell 17/19 and OpenRig 1,181/1,216. File/token windows remain
visible. Hindsight and OpenRig additionally exposed invalid native endpoints;
verified findings were retained without scoring corrupt evidence. Hindsight's
973-file independent Python complexity/dead-code run completed in 5.79 seconds;
its expensive clone search exceeded 180 seconds in diagnosis. A full scan
retains independently verified dead-code facts within one configured deadline.
A separate history probe produced ten captured revision samples rather than
failing at the former 500-file cap. These are individual adapter controls, not
whole-command timing claims.

Reproduce the released checker with any URL/pin pair above:

```sh
docker run --rm ghcr.io/react-randy/diff-gremlin:1.0.2 check \
  https://github.com/vectorize-io/hindsight \
  --ref 0be6c02b2aafc2b6bdb188ef1842ac507e0cfa2b --profile full --format json
```

Use `--profile quick` for the first pass. A missing or rejected measurement does
not become a clean result; the provisional observed score includes only valid,
complete contributing stages and shows its category weight and required-stage
coverage. Clone incidence is not a unique-line percentage.

### Public-install history provenance correction (1.0.3)

The actual 1.0.2 installer fixture was a plain folder under an unrelated Git
worktree. When its temporary snapshot also lived under that worktree, Git's
ancestor discovery returned unrelated history with an empty source commit
identity. This informational history did not affect scores, but its provenance
was wrong. Issue #52 tracks the correction: ordinary snapshots expose only
captured history, and the history reader validates the exact selected worktree
or bare-repository root before reading logs or source blobs. Native regressions
cover ancestor worktrees, ancestor bare repositories and the full acquisition
and scan path. Previously captured 1.0.2 receipts above remain historical evidence.

### Public-installed Python type evidence correction (1.0.3)

Issue #54 records a public 1.0.2 Hindsight type-transport failure: the same 973
Python source files produce 4,414,210 bytes of native Pyrefly JSON at the actual
acquisition path length, exceeding the old 4 MiB combined-output budget. A
controlled finite 64 MiB run completed in 3.249 seconds, validated all 973 files
and retained 4,469 diagnostics (3,955 missing imports). It remained LIMITED;
missing dependencies were never converted into a pass. The native regression
uses long captured paths and thousands of absent imports; a separate exhaustion
control preserves an empty, named incomplete result. This bounded transport
correction joins the history provenance fix in patch 1.0.3.
