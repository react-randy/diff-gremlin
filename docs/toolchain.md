# Reviewed toolchain

Diff Gremlin 1.0.0 uses static analyzers without target installation or builds.
Pins were reviewed on 2026-10-01, using packages available before 2026-09-24.
The package needs no model API or model-specific configuration.

| Surface | Exact tool | Observations and limits |
| --- | --- | --- |
| Python lint | Ruff 0.16.8 | Located diagnostics under scanner-owned settings |
| Python types | Pyrefly 1.3.0 | Isolated static type checks; uninstalled external imports can limit evidence |
| Python health/clones/dead code | PyScn 1.32.1 | Validated stdout JSON; optional platform wheel; full profile only |
| Complexity | Lizard 1.24.0 | Function complexity for recognized syntax; parser limits remain visible |
| Python maintainability | Radon 6.0.1 | Informational MI from the shipped driver; full profile only |
| JavaScript/TypeScript lint | ESLint 10.11.0 | Scanner-owned ESLint configuration and trusted parser/plugin packages |
| TypeScript types | TypeScript 6.0.3 | Controlled compiler host/config; unresolved target dependencies limit evidence |
| JavaScript/TypeScript clones | jscpd 4.2.3 | Scanner-owned options; full profile only |
| Java structure/types | Temurin JDK 25.0.4.1+1 in Docker | Actual JDK parser; standalone `javac -proc:none`, empty dependency paths; missing external classes limit types |
| Potential secrets | Gitleaks 8.30.1 | Pinned shipped rules, redacted JSON, target suppressions disabled; current inventoried text, not all Git history |
| Contextual security | Shipped source checks | Located Unicode/execution observations; no blanket penalty for ordinary subprocess use |
| Hygiene | Shipped inventory checks | License, README, observed test files, gitignore; presence does not prove quality |
| Python history | Shipped bounded Git/AST checks | Informational complexity samples at immutable revisions; full profile only |

Mixed repositories retain distinct stage IDs. Unsupported languages can receive
applicable inventory/security/hygiene evidence; this is not a full lint/type check
for every language. Required gaps make the score unknown. A shipped binary's
availability does not prove that a target's imports or syntax can be fully analyzed.

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

## Trusted executable discovery

Analyzer discovery uses the installed Python interpreter's directory, system
executable directories, and explicit absolute `DIFF_GREMLIN_TOOL_PATH` directories.
It excludes target-local executable directories and generic shell `PATH` additions.
For Docker, Node `.bin`, the Node binary, JDK tools, and Gitleaks have fixed trusted
paths. The curl installer places Gitleaks alongside the installed Python tool.

Analyzer processes receive a clean temporary HOME/config/cache, no provider token,
and controlled settings. uv provides dependency isolation; it does not provide an
OS sandbox. The Docker image runs non-root. Read-only mounts, dropped capabilities,
no host socket/home, and disabled local-scan network further restrict it.
