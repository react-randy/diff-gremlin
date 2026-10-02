# Reviewed toolchain

Diff Gremlin 1.0.3 uses static analyzers without target installation or builds.
Pins were reviewed on 2026-10-01, using packages available before 2026-09-24.
The package needs no model API or model-specific configuration.

| Surface | Exact tool | Observations and limits |
| --- | --- | --- |
| Python lint | Ruff 0.16.8 | Located diagnostics under scanner-owned settings |
| Python types | Pyrefly 1.3.0 | Isolated static type checks; uninstalled external imports can limit evidence |
| Python health/clones/dead code | PyScn 1.32.1 | Separate independent dead-code evidence and combined clone/health evidence; one shared deadline; full profile only |
| Python and other recognized language complexity | Lizard 1.24.0 | One observation per production function; Python AST accounts for branch-free ellipsis declarations; parser limits remain visible |
| JavaScript/TypeScript complexity | ESLint 10.11.0 | Native classic function and class initializer/static-block code paths, with independent coverage counts |
| Python maintainability | Radon 6.0.1 | Informational MI from the shipped driver; full profile only |
| JavaScript/TypeScript lint | ESLint 10.11.0 | Scanner-owned ESLint configuration and trusted parser/plugin packages |
| TypeScript types | TypeScript 6.0.3 | Controlled compiler host/config; unresolved target dependencies limit evidence |
| JavaScript/TypeScript clones | jscpd 4.2.3 | Scanner-owned options; full profile only |
| Java structure/types | Temurin JDK 25.0.4.1+1 in Docker | Actual JDK parser; standalone `javac -proc:none`, empty dependency paths; missing external classes limit types |
| Potential secrets | Gitleaks 8.30.1 | Pinned shipped rules, redacted JSON, target suppressions disabled; current inventoried text, not all Git history |
| Shell syntax/complexity | shfmt 3.14.1 | Declared POSIX sh/dash, Bash and mksh; bounded validated AST; function decision estimate v1 |
| Contextual security | Shipped source checks | Located Unicode/execution observations; no blanket penalty for ordinary subprocess use |
| Hygiene | Shipped inventory checks | License, README, observed test files, gitignore; presence does not prove quality |
| Python history | Shipped bounded Git/AST checks | Immutable samples, metadata-sized blob batches, up to 20,000 files/256 MiB per commit and 8 MiB per file; full profile only |

Mixed repositories retain distinct stage IDs. Unsupported languages can receive
applicable inventory/security/hygiene evidence; this is not a full lint/type check
for every language. Required gaps keep the strict score unknown; provisional
observed scores show their measured stage/category scope. A shipped binary's
availability does not prove that a target's imports or syntax can be fully analyzed.

## Shell evidence

[shfmt 3.14.1](https://github.com/mvdan/sh/releases/tag/v3.14.1), published
2026-09-06, is pinned to commit
`a3f0c75d21d918756fa38de8b5d3429efde7948b`. Its BSD 3-Clause license is shipped.
The provisioner checks the official platform binary and pinned license hashes
before publication. The parser receives source on stdin and an owned explicit
dialect; it never sources the script or invokes its interpreter.

Syntax checks cover all inventoried Shell; complexity covers production Shell.
A supported shebang is required, including plain `env` and `env -S` forms.
Unknown dialects, options, resource caps and invalid parser output remain explicit
evidence gaps. POSIX/Bash/mksh support does not imply fish, zsh or PowerShell support.

The `shell-ast-decision-complexity-v1` estimate starts each function at one and
counts if/elif, loops/select, command/test Boolean operators, and case arms minus
one. Shared case patterns count as one arm. Pipelines, negation and arithmetic
operators add no decisions. Nested functions own their bodies; substitutions in
the current function count. This is a documented AST estimate, not exact runtime
paths or identical counting across languages. Ordinary commands are observations;
command arguments and raw ASTs never enter reports. Alias/function resolution,
expansions and runtime reachability remain uncertain.

Ordinary dynamic command names and sourced paths are informational observations;
they do not establish a defect. `eval` and recognized interpreter command strings
remain high-severity review points. Known interpreter option operands are consumed
before recognizing `-c`/`+c`; unknown options and script operands stop recognition.

## Native clone evidence

JavaScript/TypeScript clone checks retain jscpd's five-line/50-token minimum and
1,000-line/100-KiB file limits. Native tokenizer identities determine which sources
were observed. Filtered sources remain an evidence gap, even when the tool reports
zero clones. A five-line source below the token window can have genuine zero clone
observations; this does not prove that shorter similarities are absent.

Clone ranges must fit the copied source, including UTF-16 columns and native line
boundaries. The measure `jscpd-native-clone-incidence-v1` sums native clone
incidences; it is not the share of unique duplicated lines. Overlapping clones
can make a per-source incidence percentage exceed 100. Counter/ratio checks and
the trusted tokenizer's embedded-format catalog validate this native behavior.

jscpd 4.2.3 can produce impossible second clone endpoints while extending a
match across sources. Recognized coordinate-invalid records are counted and
rejected; verified clone findings remain visible with **limited** evidence.
When this occurs, the native incidence percentage is unscored telemetry and
`duplication_percent` is absent. No location is repaired or reordered. Foreign
identities, malformed schemas, stale or oversized reports still fail the check;
report reads are capped at 4 MiB. Raw reports and source fragments are private.

## Python delivery

`toolchain/python/core-requirements.txt` and `full-requirements.txt` pin direct and
transitive analyzer dependencies with wheel hashes. `build-requirements.txt` pins
uv_build 0.12.18. The public source lock records development dependencies too.
Third-party source builds are disabled in the installer and Docker dependency
steps. The trusted package itself is built through the pinned backend.

[PyScn 1.32.1 release metadata](https://pypi.org/pypi/pyscn/1.32.1/json) lists
macOS ARM64 ≥11, Linux x64/ARM64 glibc ≥2.34, and Windows x64 wheels, uploaded
2026-09-20. Other platforms need core coverage or Docker; see the platform matrix.
[uv 0.12.18](https://github.com/astral-sh/uv/releases/tag/0.12.18) was published
2026-09-22. Bootstrap archives are matched against fixed reviewed official SHA-256
values before execution. Gitleaks
[8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) was published
2026-03-21; its provisioner pins official archive hashes for four supported platforms.

## Node delivery

`toolchain/node/package-lock.json` includes integrity hashes. `npm ci --ignore-scripts`
installs only this trusted lock. The exact direct dependency set is:
ESLint 10.11.0, `@eslint/js` 10.0.1, `@typescript-eslint/parser` and plugin 8.70.1,
`globals` 17.12.0, TypeScript 6.0.3, and jscpd 4.2.3. These are reviewed tooling
packages. No target `package.json`/lockfile/config/plugin can add packages or code
to this environment. The isolated dependency review reported no npm audit
vulnerabilities on 2026-10-01; this is a dated audit result, not a security guarantee.

## Docker provenance

The Dockerfile pins official multiarch index digests verified from registry
manifests on 2026-10-01:

| Base | Index SHA-256 |
| --- | --- |
| `python:3.12.12-slim-bookworm` | `593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c` |
| `node:22.23.1-bookworm-slim` | `6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| `eclipse-temurin:25.0.4.1_1-jdk-noble` | `f6366ccac38ceae180280ad7012d18a15e8031548a430dc2bae06631d9e88ed0` |
| `ghcr.io/astral-sh/uv:0.12.18` | `3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc` |

Node [22.23.1](https://github.com/nodejs/node/releases/tag/v22.23.1) was published
2026-06-23; Temurin
[25.0.4.1+1](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.4.1%2B1)
was published 2026-08-19. Debian runtime packages resolve from the fixed
2026-09-24 [Debian snapshot](https://snapshot.debian.org/) sources; refreshing them
requires explicit lock/provenance review and rebuilding/retesting the image.
Image digest identity is distinct from release publication age or a passing
runtime test. Current Docker CI results are the evidence of build/run support.

## Controlled rule provenance

The shipped Gitleaks configuration starts from the [exact upstream rules commit](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/config/gitleaks.toml).
All 222 rule identifiers and their entropy thresholds, rule allowlists and stopwords
remain. We removed the global filename exclusions so a lockfile can still contain
a finding. The short-lived Bedrock rule now requires the complete signed payload
instead of matching its public service marker. Its format follows the
[pinned AWS generator](https://github.com/aws/aws-bedrock-token-generator-python/blob/228eec2bfcf209d53dc776c902e00d9e6548e508/aws_bedrock_token_generator/token_generator.py#L41).
Synthetic positives cover Base64 alignment and optional session credentials;
truncated, unsigned and ordinary-text controls stay clean. The rule recognizes
that generator's ordering; it does not authenticate credentials or recognize
arbitrary reordered encodings.

The full shipped configuration SHA-256 is
`38cea322df5f9b983be9cd57ad0a70720e8d876bc0283fc8d6c3c821aa431b5c`.
The modified rules body SHA-256 is
`89c72f76660e87008ec265b175acce1df9cc995d8075e4a9a81d7524b5ae7abe`.

JavaScript execution observations use isolated TypeScript lexical symbols for
imports, local variables, parameters and aliases. JavaScript retains its own
correctness rules; TypeScript rules apply to TypeScript. Binding observations
remain a syntax approximation without flow, runtime reachability or inter-file
analysis. Complete source parsing does not make those observations exhaustive.

Python execution observations include eager function/lambda defaults and class
keyword expressions. Comprehension targets own inner expressions; only the first
iterable uses the enclosing scope. These are lexical observations, including
possible unbound locals; they do not establish whether a call can run.

Java distinguishes `Runtime.exec(String)` tokenization from `ProcessBuilder`
command vectors. A single builder string is one program name. Recognized literal
shell command options are review points; dynamic arguments, unsupported options,
script operands and runtime reachability remain unresolved. Windows interpreter
forms have static fixture coverage, without a claim of Windows runtime testing.

Located JS/TS and JDK diagnostics must fit the invocation's copied source. Each
located report uses the captured source sizes, an 8-MiB per-file read bound,
a 256-MiB cumulative read bound, and a separate two-million-line cache bound.
Read sizes must match the captured inventory. JavaScript coordinates
use UTF-16 units and native line separators; compiler/lint BOM handling is distinct
from the syntax observer. JDK columns include eight-column tab stops, with
separate tree and diagnostic EOF conventions. Unreadable sources, invalid
coordinates and exhausted budgets lose coverage; validating an extent does not
prove the diagnostic's meaning.

## Trusted executable discovery

Analyzer discovery uses the installed Python interpreter's directory, system
executable directories, and explicit absolute `DIFF_GREMLIN_TOOL_PATH` directories.
It excludes target-local executable directories and generic shell `PATH` additions.
For Docker, Node `.bin`, the Node binary, JDK tools, Gitleaks and shfmt have fixed trusted
paths. The curl installer places Gitleaks and shfmt alongside the installed Python tool.

Analyzer processes receive a clean temporary HOME/config/cache, no provider token,
and controlled settings. uv provides dependency isolation; it does not provide an
OS sandbox. The Docker image runs non-root. Read-only mounts, dropped capabilities,
no host socket/home, and disabled local-scan network further restrict it.

Native Pyrefly JSON diagnostics have a finite 64 MiB transport budget. Missing
imports can repeat long snapshot/search paths across thousands of messages;
the old shared 4 MiB cap discarded valid evidence for normal repositories.
Exhausting the type-specific budget is explicitly limited and supplies no clean
score. Target imports remain uninstalled and unresolved dependencies remain
visible even when all diagnostic rows validate.
