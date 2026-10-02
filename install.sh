#!/bin/sh
# Install the pinned Diff Gremlin release into a user-local uv tool environment.
set -eu

VERSION=1.0.3
UV_VERSION=0.12.18
PYTHON_VERSION=3.12.12
RELEASE_URL=https://github.com/react-randy/diff-gremlin/releases/download/v1.0.3
# The release owner fills this after building the final wheel. Never bypass this gate.
RELEASE_WHEEL_SHA256=REPLACE_WITH_FINAL_RELEASE_WHEEL_SHA256
CORE_LOCK_SHA256=c20982ad0e9a87d533b0c90333cf121590b2708467aa0f8d5a9a91f6d996be1a
FULL_LOCK_SHA256=49350b2248a6208b2a156abca7a9305bc5945755d8dc8adf015b1f00572b52bf
GITLEAKS_SCRIPT_SHA256=04512be352ff4bdeb26167167227422a35243213212d928c54c6c28baedbef44
SHFMT_SCRIPT_SHA256=4d0aec9eaf38a448eb2810e32c319be288f10be615419a5eb2a71e31f57fdd89
DOWNLOAD_SCRIPT_SHA256=b5e14f72993de145781df7fb87a8bf871ef2b5702bcc2e8a5b71c756a8e8ca18

fail() {
    printf 'diff-gremlin install: %s\n' "$*" >&2
    exit 1
}

checksum() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        fail 'SHA-256 verifier unavailable; install sha256sum or shasum.'
    fi
}

verify() {
    actual=$(checksum "$1")
    [ "$actual" = "$2" ] || fail "checksum mismatch: $(basename "$1"); nothing from this download was executed."
}

download() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 180 --retry 2 --output "$2" "$1" \
        || fail "download failed: $(basename "$2"); check network access and the v$VERSION release."
}

uv_asset() {
    case "$system:$machine:$libc" in
        Darwin:arm64:*)
            uv_target=aarch64-apple-darwin
            uv_hash=cf40e0c6a202190ccd9e0406dcfdd5b2d6668a9a5c779b17948963df32aafe5b ;;
        Darwin:x86_64:*)
            uv_target=x86_64-apple-darwin
            uv_hash=2e4108f5395397c8bc5d43bf83d3bdbb2d0e92b90d0efa607756be704905fa33 ;;
        Linux:aarch64:glibc)
            uv_target=aarch64-unknown-linux-gnu
            uv_hash=afb6291f3f0a6b4521fc67b947822506c41dde5b60d2189dd8f3695b2ac8c9e7 ;;
        Linux:x86_64:glibc)
            uv_target=x86_64-unknown-linux-gnu
            uv_hash=89eadd7c76fc063887959510d5ba0ab1264dfd5f1143b925ddb73021a40acf16 ;;
        Linux:aarch64:musl)
            uv_target=aarch64-unknown-linux-musl
            uv_hash=0796973fb3eea8095078c3d0659bd17a5f6789a71b8dd85caff2483178f78ac3 ;;
        Linux:x86_64:musl)
            uv_target=x86_64-unknown-linux-musl
            uv_hash=e38d97460b98ebfd31b197de0fe9fa578add4bc8ba0179b203dd3f87b99f98e6 ;;
        *) fail "unsupported installer platform: $system/$machine; use Docker or the manual wheel route." ;;
    esac
}

bootstrap_uv() {
    if command -v uv >/dev/null 2>&1 && [ "$(uv --version)" = "uv $UV_VERSION" ]; then
        uv_command=$(command -v uv)
        return
    fi
    uv_asset
    uv_archive="$install_temp/uv.tar.gz"
    download "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-$uv_target.tar.gz" "$uv_archive"
    verify "$uv_archive" "$uv_hash"
    tar -xzf "$uv_archive" -C "$install_temp" "uv-$uv_target/uv" \
        || fail 'verified uv archive could not be extracted.'
    uv_directory="${XDG_DATA_HOME:-$HOME/.local/share}/diff-gremlin/uv/$UV_VERSION"
    mkdir -p "$uv_directory"
    cp "$install_temp/uv-$uv_target/uv" "$uv_directory/uv"
    chmod 755 "$uv_directory/uv"
    uv_command="$uv_directory/uv"
}

select_profile() {
    profile=core
    if [ "$system:$machine" = 'Darwin:arm64' ]; then
        profile=full
    elif [ "$system" = Linux ] && [ "$libc" = glibc ]; then
        glibc_version=$(getconf GNU_LIBC_VERSION | awk '{print $2}')
        if printf '%s\n' "$glibc_version" | awk -F. '{exit !($1 > 2 || ($1 == 2 && $2 >= 34))}'; then
            profile=full
        fi
    fi
    if [ "$profile" = core ]; then
        printf 'PyScn has no compatible reviewed wheel here; installing core coverage. Full Python checks will report missing PyScn.\n' >&2
    fi
}

fetch_release() {
    wheel="$install_temp/diff_gremlin-$VERSION-py3-none-any.whl"
    lock="$install_temp/$profile-requirements.txt"
    download "$RELEASE_URL/$(basename "$wheel")" "$wheel"
    verify "$wheel" "$RELEASE_WHEEL_SHA256"
    download "$RELEASE_URL/$profile-requirements.txt" "$lock"
    if [ "$profile" = full ]; then lock_hash=$FULL_LOCK_SHA256; else lock_hash=$CORE_LOCK_SHA256; fi
    verify "$lock" "$lock_hash"
    download "$RELEASE_URL/provision_gitleaks.py" "$install_temp/provision_gitleaks.py"
    verify "$install_temp/provision_gitleaks.py" "$GITLEAKS_SCRIPT_SHA256"
    download "$RELEASE_URL/provision_shfmt.py" "$install_temp/provision_shfmt.py"
    verify "$install_temp/provision_shfmt.py" "$SHFMT_SCRIPT_SHA256"
    download "$RELEASE_URL/download_asset.py" "$install_temp/download_asset.py"
    verify "$install_temp/download_asset.py" "$DOWNLOAD_SCRIPT_SHA256"
}

verify_dependencies() {
    "$uv_command" --no-config venv --python "$PYTHON_VERSION" "$install_temp/verification" \
        || fail "Python $PYTHON_VERSION environment creation failed."
    verification_python="$install_temp/verification/bin/python"
    "$uv_command" --no-config pip install --python "$verification_python" --require-hashes \
        --only-binary :all: --default-index https://pypi.org/simple -r "$lock" \
        || fail 'hash-locked wheel dependency installation failed; no tool environment was installed.'
}

install_tool() {
    package="$wheel"
    if [ "$profile" = full ]; then package="$wheel[full]"; fi
    "$uv_command" --no-config tool install --offline --no-build --python "$PYTHON_VERSION" \
        --constraints "$lock" "$package" \
        || fail 'offline installation from verified wheels failed.'
    tool_directory=$("$uv_command" --no-config tool dir)
    tool_python="$tool_directory/diff-gremlin/bin/python"
    "$tool_python" -I "$install_temp/provision_gitleaks.py" "$tool_directory/diff-gremlin/bin" \
        || fail 'Gitleaks installation failed; Diff Gremlin is installed with incomplete security coverage. Rerun this installer to repair it.'
    "$tool_python" -I "$install_temp/provision_shfmt.py" "$tool_directory/diff-gremlin/bin" \
        || fail 'shfmt installation failed; Diff Gremlin is installed with incomplete Shell coverage. Rerun this installer to repair it.'
}

show_result() {
    bin_directory=$("$uv_command" --no-config tool dir --bin)
    "$bin_directory/diff-gremlin" --version
    printf '\nInstalled %s profile. Run: %s/diff-gremlin doctor\n' "$profile" "$bin_directory"
    printf 'If needed, add this directory to PATH: %s\n' "$bin_directory"
    printf 'Uninstall: "%s" tool uninstall diff-gremlin\n' "$uv_command"
    printf 'For TypeScript/Java and the complete bundled toolchain, use Docker.\n'
}

main() {
    [ "$#" -eq 0 ] || fail 'this installer takes no arguments.'
    case "$RELEASE_WHEEL_SHA256" in REPLACE_*) fail 'release wheel hash is not finalized; this installer is not ready for publication.' ;; esac
    command -v curl >/dev/null 2>&1 || fail 'curl is required.'
    command -v tar >/dev/null 2>&1 || fail 'tar is required.'
    system=$(uname -s)
    machine=$(uname -m)
    libc=glibc
    if [ "$system" = Linux ] && ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then libc=musl; fi
    install_temp=$(mktemp -d "${TMPDIR:-/tmp}/diff-gremlin-install.XXXXXX")
    trap 'rm -rf "$install_temp"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # A private cache keeps offline tool resolution bound to verified downloads.
    export UV_CACHE_DIR="$install_temp/cache"
    bootstrap_uv
    select_profile
    fetch_release
    verify_dependencies
    install_tool
    show_result
}

main "$@"
