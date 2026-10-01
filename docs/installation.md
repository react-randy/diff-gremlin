# Installation

Use Docker for the complete bundled cross-language toolchain. Use the curl
installer for a user-local Python toolchain with Gitleaks and Shell parsing. Run `diff-gremlin doctor`
to see actual installed capabilities before scanning. Git must be installed for
repository URLs, refs, comparisons, and history; the curl installer does not
install system packages.

Commands below use versioned GitHub release assets and the GHCR image. Nothing
here assumes a PyPI publication. A [source installation](#from-source) is also
available for development.

## Curl installer

```sh
curl -fsSL https://github.com/react-randy/diff-gremlin/releases/download/v1.0.1/install.sh | sh
```

For inspection before execution, download the same pinned release file:

```sh
curl -fsSLO https://github.com/react-randy/diff-gremlin/releases/download/v1.0.1/install.sh
less install.sh
sh install.sh
```

The installer verifies a fixed wheel SHA-256, verified core/full requirement
files, both Gitleaks and shfmt provisioners, and their shared HTTPS download helper.
It uses uv 0.12.18 and Python 3.12.12. If your
`uv` version differs, the installer places a verified uv binary in
`${XDG_DATA_HOME:-$HOME/.local/share}/diff-gremlin/uv/0.12.18/`; it does not replace
your existing uv executable. uv supplies the exact Python interpreter if missing.

Third-party dependencies are wheels only. A temporary environment first downloads
and checks every dependency hash. The final uv tool install runs offline from
that private verified cache. Gitleaks 8.30.1 is independently hash-checked and placed
inside the tool environment. shfmt 3.14.1 and its BSD license are independently
hash-checked in the same tool environment. Network/hash errors stop installation with an explicit
error. If either native provisioner fails after the Python tool is installed, installation
exits nonzero and reports the incomplete native coverage; rerun the installer.
Each native asset transfer has a 60-second total deadline and a byte limit,
including redirects and continuously slow responses. The verified helpers run
under isolated Python and load only their adjacent verified download helper.

Executables use uv's bin directory (normally `$HOME/.local/bin`). The installer
prints the actual directory and command to add it to your shell's `PATH`; it
never edits shell startup files. `UV_TOOL_DIR` and `UV_TOOL_BIN_DIR` can select
other user-owned directories. Never run the installer with `sudo`.

### Platform coverage

| Platform | Curl installer | PyScn 1.32.1 full Python coverage |
| --- | --- | --- |
| Linux x64/ARM64, glibc ≥2.34 | Supported installer assets | Reviewed wheels available |
| Linux x64/ARM64, glibc <2.34 | Core selection; Python/core dependencies still need compatible wheels | Unavailable |
| Linux x64/ARM64, musl | Core selection; Python/core dependencies still need compatible wheels | Unavailable |
| macOS ARM64 ≥11 | Supported installer assets | Reviewed wheel available |
| macOS Intel | Core selection; core dependencies still need compatible wheels | Unavailable |
| Windows x64 | Manual uv/wheel route | Reviewed PyScn wheel available |
| Windows ARM64 | Manual route needs compatible core wheels | Unavailable |
| Other architectures | Use a supported Docker host or provide a reviewed toolchain | Unverified |

“Available wheel” is release metadata, not a claim that every platform has passed
end-to-end installation. Installer/platform tests and native Docker CI provide the
actual validation evidence. Old glibc, musl, and Windows ARM core dependencies
remain unverified. Core mode does not relabel a missing full stage as passing.
Docker targets Linux amd64/arm64 and supplies a compatible glibc runtime.

## Docker

```sh
docker run --rm ghcr.io/react-randy/diff-gremlin:1.0.1 doctor
docker run --rm ghcr.io/react-randy/diff-gremlin:1.0.1 check https://github.com/OWNER/REPO
docker run --rm ghcr.io/react-randy/diff-gremlin:1.0.1 pr https://github.com/OWNER/REPO/pull/123
```

The image runs as UID/GID 10001. It includes the pinned Python, Node, JDK 25, and
Gitleaks and shfmt tools. PR/MR URLs and Git HTTPS URLs need outbound network access. The
image receives no host home directory, Docker socket, provider login, or token
unless you explicitly supply one.

For a local repo, including paths with spaces:

```sh
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --network=none --tmpfs /tmp:rw,nosuid,nodev,size=1g \
  --mount "type=bind,src=$PWD,dst=/workspace,readonly" \
  ghcr.io/react-randy/diff-gremlin:1.0.1 check /workspace --format json
```

The non-root account must be able to read the mounted files. If the repository
is private to your host UID, add `--user "$(id -u):$(id -g)"`. Keep the mount read-only.
The scanner writes disposable analysis state under `/tmp`. It does not use Maven,
Gradle, npm, or pip to install anything from the target. For a local Git comparison,
replace the final command with `compare /workspace main HEAD`.

## Existing uv: one-off Python checks

This exact release URI avoids assuming a public package registry entry:

```sh
uvx --no-build --exclude-newer 2026-09-24 \
  --from 'https://github.com/react-randy/diff-gremlin/releases/download/v1.0.1/diff_gremlin-1.0.1-py3-none-any.whl' \
  diff-gremlin check . --profile quick
```

This minimal alternative does not install Gitleaks, shfmt, Node, JDK, or PyScn. Missing
required tools remain visible and produce exit 3. Prefer the verified curl installer
for persistent Python use. uv itself must be installed from a trusted source.

## From source

Use a reviewed checkout of this repository. Do not install or build a repository
that you only intended to scan.

```sh
git clone https://github.com/react-randy/diff-gremlin.git
cd diff-gremlin
uv sync --locked --extra full
uv run diff-gremlin doctor
uv run diff-gremlin check . --profile quick
```

For the full Docker image from a trusted checkout:

```sh
docker build --tag diff-gremlin:local .
docker run --rm diff-gremlin:local doctor
```

The source environment alone does not supply Gitleaks/shfmt/Node/JDK. See
[development](development.md) and [toolchain](toolchain.md) for explicit setup.

## Uninstall

```sh
uv tool uninstall diff-gremlin
```

If the installer bootstrapped a private uv, use the exact uninstall command it
printed, or:

```sh
"${XDG_DATA_HOME:-$HOME/.local/share}/diff-gremlin/uv/0.12.18/uv" tool uninstall diff-gremlin
```

This removes the tool environment, its Gitleaks and shfmt binaries/licenses, and its console
entry points (`diff-gremlin` and `vibe-check`). Remove only the installer-owned
`diff-gremlin/uv/0.12.18` directory if you no longer need its private uv. uv-managed
Python and other uv caches may be shared by your other tools; use uv's own management
commands to inspect them before removal. Source checkouts and Docker images are
separate installations.
