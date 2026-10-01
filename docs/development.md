# Development

Develop only from a trusted checkout. Installing this project is an execution
boundary; scanning another project never authorizes installing or building it.

## Set up

Python requires ≥3.12. Dependency versions and hashes are recorded in `uv.lock`.
The source manifest uses a 2026-09-24 package maturity cutoff and uv_build 0.12.18.

```sh
uv sync --locked --extra full
uv run diff-gremlin --help
```

PyScn must have a compatible platform wheel; consult the
[installation matrix](installation.md#platform-coverage). Missing optional tools
must remain visible. Do not add target-package installation as a fallback.

For reviewed cross-language analyzer dependencies:

```sh
npm --prefix toolchain/node ci --ignore-scripts --no-audit --no-fund
uv run python scripts/provision_gitleaks.py .venv/bin
uv run python scripts/provision_shfmt.py .venv/bin
export DIFF_GREMLIN_TOOL_PATH="$PWD/toolchain/node/node_modules/.bin:$(dirname "$(command -v node)"):$JAVA_HOME/bin"
uv run diff-gremlin doctor
```

Supply a separately trusted JDK 25 through `JAVA_HOME` for Java controls. These
commands install only Diff Gremlin's reviewed toolchain, not target dependencies.
The Gitleaks provisioner verifies official archive hashes before extracting the
binary and license. It supports Linux and macOS x64/arm64. The locked Node manifest
contains exact analyzer versions; all npm lifecycle scripts are disabled.

## Validate

```sh
uv run ruff check .
uv run pyrefly check
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run pytest
sh -n install.sh
uv build --wheel --require-hashes --build-constraints toolchain/python/build-requirements.txt
```

Check fixtures independently of this repository's own score. A clean control, a
known bad control, mixed-language evidence, missing/malformed/failed tools, and
nonmutation/security failures each answer different questions. A high self-score
cannot replace those controls.

For real container validation:

```sh
docker build --tag diff-gremlin:ci .
python3 scripts/verify_docker.py diff-gremlin:ci
```

The Docker check exercises help, all discovered tool executables, and actual
Python/TypeScript/Java/Shell/secrets adapters against a trusted mixed-language control
with a space in its mount path. It requires read-only mounts and verifies unchanged
source bytes. It never runs the control's npm/Gradle wrapper. The GitHub workflow
runs native amd64 and arm64 Docker jobs; a checked-in workflow is not itself a
passing build. Review actual CI results before publishing.

## Structure

Follow [architecture](architecture.md): acquisition owns snapshots, adapters
report observations, policy interprets them, and reports present the same evidence.
Each function performs one operation. Each file owns one concern. Errors name the
failed operation and preserve uncertainty; never score an empty failed result as
clean. Add behavior fixtures beside the affected capability.

## Release

A release owner builds the final package after documentation/source review,
verifies shipped analyzer assets, and freezes the resulting wheel bytes. Run:

```sh
uv build --wheel --require-hashes --build-constraints toolchain/python/build-requirements.txt
python3 scripts/prepare_release.py dist/diff_gremlin-1.0.0-py3-none-any.whl
```

The preparation script verifies package identity/required assets, fills the
installer's fixed wheel SHA, and stages only public release assets under
`dist/release/`. It never publishes. Upload that directory to the owned v1.0.0
GitHub release only after full CI, independent review, installer end-to-end tests,
and platform claims match the evidence. The release has these assets:

- `diff_gremlin-1.0.0-py3-none-any.whl`
- `install.sh`
- `core-requirements.txt`, `full-requirements.txt`
- `provision_gitleaks.py`
- `provision_shfmt.py`, `download_asset.py`
- `SHA256SUMS`

Publish the separately validated full image as
`ghcr.io/react-randy/diff-gremlin:1.0.0`, retaining its immutable digest in the release
record. Preserve both Linux architectures only after their native tests pass.
The publication workflow runs release helpers as modules from the trusted checkout
root (`python3 -m scripts.image_publication`). It requires the published stable
release tag, checkout and current main to name the same commit. Both native runtime
controls and digest receipts must pass before the version index is created. The
package owner then makes the GHCR package public and verifies anonymous pulls.
Workflow concurrency serializes this repository's publishers; the registry does
not provide an atomic create-if-absent operation against unrelated publishers.
Then test the public curl command in disposable `UV_TOOL_DIR`/`UV_TOOL_BIN_DIR`
directories and verify uninstall. Update release-readiness prose before the final
wheel build; editing README afterward changes package metadata and invalidates the
wheel checksum. `install.sh` lives outside the wheel to avoid a circular checksum.

Do not commit release wheels, node_modules, local virtual environments, caches,
logs, private contracts, or credentials. Preserve the original MIT attribution.
