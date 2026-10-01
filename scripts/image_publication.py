"""Check the fixed Diff Gremlin release and its container publication receipts."""

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPOSITORY = "react-randy/diff-gremlin"
REPOSITORY_ID = 1400500531
IMAGE = f"ghcr.io/{REPOSITORY}"
TAG = "v1.0.0"
VERSION = "1.0.0"
ARCHITECTURES = ("amd64", "arm64")
MANIFEST_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)


class PublicationRedirects(urllib.request.HTTPRedirectHandler):
    """Keep registry credentials on the same HTTPS origin during redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        before = urllib.parse.urlsplit(req.full_url)
        after = urllib.parse.urlsplit(newurl)
        if after.scheme != "https" or after.netloc != before.netloc:
            raise urllib.error.URLError("Publication metadata redirected outside its origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def require(condition: bool, message: str) -> None:
    """Reject a failed publication condition with safe operation context."""
    if not condition:
        raise ValueError(message)


def sha(value: str) -> str:
    """Accept only a complete Git commit identity."""
    require(bool(re.fullmatch(r"[0-9a-f]{40}", value)), "Invalid source commit identity")
    return value


def digest(value: str) -> str:
    """Accept only a complete SHA-256 registry digest."""
    require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value)), "Invalid image digest")
    return value


def http_json(url: str, headers: dict[str, str]) -> tuple[int, dict]:
    """Read bounded official metadata without including response bodies in errors."""
    request = urllib.request.Request(url, headers=headers)
    try:
        response = urllib.request.build_opener(PublicationRedirects()).open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(1024 * 1024 + 1)
        require(len(body) <= 1024 * 1024, "Publication metadata exceeds the size limit")
        result = json.loads(body)
        require(isinstance(result, dict), "Publication metadata must be a JSON object")
        return response.code, result


def github_metadata(endpoint: str) -> dict:
    """Read this public repository's live metadata without a secret."""
    status, result = http_json(
        f"https://api.github.com/repos/{REPOSITORY}/{endpoint}",
        {"Accept": "application/vnd.github+json", "User-Agent": "diff-gremlin-publication"},
    )
    require(status == 200, f"GitHub publication identity lookup failed (HTTP {status})")
    return result


def validate_repository(context: dict, repository: dict) -> None:
    """Require the authorized public repository and its main branch."""
    require(context["GITHUB_REPOSITORY"] == REPOSITORY, "Unexpected workflow repository")
    require(context["GITHUB_REPOSITORY_ID"] == str(REPOSITORY_ID), "Unexpected repository ID")
    require(repository.get("full_name") == REPOSITORY, "Repository lookup identity mismatch")
    require(repository.get("id") == REPOSITORY_ID, "Repository lookup ID mismatch")
    require(repository.get("private") is False, "Publication requires the owned public repo")
    require(repository.get("default_branch") == "main", "Unexpected default branch")


def validate_release(release: dict) -> None:
    """Require the fixed published stable release."""
    require(release.get("tag_name") == TAG, "Unexpected release tag")
    require(release.get("draft") is False, "Draft release cannot publish an image")
    require(release.get("prerelease") is False, "Prerelease cannot publish an image")
    require(bool(release.get("published_at")), "Release has not been published")
    require(type(release.get("id")) is int, "Missing stable release identity")


def validate_event(context: dict, event: dict, release: dict) -> None:
    """Accept dispatch from main or the exact published-release event."""
    event_name = context["GITHUB_EVENT_NAME"]
    if event_name == "workflow_dispatch":
        require(context["GITHUB_REF"] == "refs/heads/main", "Dispatch must run from main")
        require(event.get("inputs", {}).get("tag") == TAG, "Dispatch must name v1.0.0")
        return
    require(event_name == "release", "Unsupported publication event")
    require(event.get("action") == "published", "Release event must be published")
    require(context["GITHUB_REF"] == f"refs/tags/{TAG}", "Release ref mismatch")
    event_release = event.get("release", {})
    validate_release(event_release)
    require(event_release["id"] == release["id"], "Release event identity has changed")


def validate_source(context: dict, tag_sha: str, main_sha: str, expected: str | None) -> str:
    """Require immutable checkout, release tag and current main to agree."""
    source = sha(tag_sha)
    require(source == sha(main_sha), "Release tag does not match current main")
    require(source == sha(context["GITHUB_SHA"]), "Workflow checkout does not match release")
    if expected is not None:
        require(source == sha(expected), "Publication source changed after the identity gate")
    return source


def guard(expected: str | None, release_id: str | None = None) -> None:
    """Resolve and recheck live release identity before each publication transition."""
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    repository = github_metadata("")
    release = github_metadata(f"releases/tags/{TAG}")
    validate_repository(dict(os.environ), repository)
    validate_release(release)
    if release_id is not None:
        require(str(release["id"]) == release_id, "Published release identity changed during run")
    validate_event(dict(os.environ), event, release)
    source = validate_source(
        dict(os.environ),
        github_metadata(f"commits/{TAG}")["sha"],
        github_metadata("commits/main")["sha"],
        expected,
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"sha={source}\nversion={VERSION}\nrelease_id={release['id']}\n")
    print(f"Verified {REPOSITORY} release {TAG} at {source}")


def registry_token(config: Path) -> str:
    """Exchange isolated Docker login credentials for a scoped GHCR read token."""
    auth = json.loads((config / "config.json").read_text())["auths"]["ghcr.io"]["auth"]
    require(isinstance(auth, str) and bool(auth), "Missing isolated GHCR login credentials")
    try:
        base64.b64decode(auth, validate=True)
    except ValueError:
        raise ValueError("Malformed isolated GHCR login credentials") from None
    status, result = http_json(
        f"https://ghcr.io/token?service=ghcr.io&scope=repository:{REPOSITORY}:pull",
        {"Authorization": f"Basic {auth}"},
    )
    require(status == 200, f"GHCR authentication failed (HTTP {status})")
    token = result.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("GHCR authentication returned no token")
    require(bool(re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token)), "Malformed GHCR read token")
    return token


def validate_absence(status: int, body: dict) -> None:
    """Only a registry's explicit authenticated missing-manifest response means absent."""
    require(status != 200, "Refusing to overwrite existing image version 1.0.0")
    require(status == 404, f"GHCR version lookup failed (HTTP {status}); absence unproven")
    errors = body.get("errors")
    if not isinstance(errors, list) or not errors:
        raise ValueError("GHCR absence response lacks errors")
    require(
        all(
            isinstance(e, dict) and e.get("code") in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN")
            for e in errors
        ),
        "GHCR version lookup did not prove manifest absence",
    )


def require_absent(config: Path) -> None:
    """Fail closed before pushing staging images or creating the version index."""
    token = registry_token(config)
    status, body = http_json(
        f"https://ghcr.io/v2/{REPOSITORY}/manifests/{VERSION}",
        {"Authorization": f"Bearer {token}", "Accept": ", ".join(MANIFEST_TYPES)},
    )
    validate_absence(status, body)
    print(f"Verified {IMAGE}:{VERSION} does not exist")


def receipt_identity(architecture: str, source: str, run_id: str, attempt: str) -> dict:
    """Bind a successful native build receipt to its source and workflow attempt."""
    require(architecture in ARCHITECTURES, "Unsupported native image architecture")
    require(run_id.isdigit() and attempt.isdigit(), "Invalid workflow run identity")
    return {
        "architecture": architecture,
        "source": sha(source),
        "image": IMAGE,
        "version": VERSION,
        "run_id": run_id,
        "attempt": attempt,
    }


def write_receipt(args: argparse.Namespace) -> None:
    """Record one validated locally built and successfully pushed native image."""
    receipt = receipt_identity(args.architecture, args.sha, args.run_id, args.attempt)
    require(args.platform == f"linux/{args.architecture}", "Built image platform mismatch")
    references = json.load(sys.stdin)
    require(isinstance(references, list) and len(references) == 1, "Ambiguous pushed digest")
    reference = references[0]
    require(
        isinstance(reference, str) and reference.startswith(f"{IMAGE}@"),
        "Pushed digest names an unexpected image",
    )
    receipt["digest"] = digest(reference.removeprefix(f"{IMAGE}@"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, sort_keys=True) + "\n")


def read_receipts(directory: Path, source: str, run_id: str, attempt: str) -> dict[str, str]:
    """Require exactly one current-attempt receipt for each required architecture."""
    paths = sorted(directory.glob("*/*.json"))
    require(len(paths) == 2, "Expected exactly two native image receipts")
    result = {}
    for path in paths:
        receipt = json.loads(path.read_text())
        architecture = receipt.get("architecture")
        expected = receipt_identity(architecture, source, run_id, attempt)
        require(set(receipt) == {*expected, "digest"}, "Unexpected native receipt fields")
        require(all(receipt[k] == v for k, v in expected.items()), "Receipt identity mismatch")
        require(architecture not in result, "Duplicate native architecture receipt")
        result[architecture] = digest(receipt["digest"])
    require(set(result) == set(ARCHITECTURES), "Incomplete native architecture receipts")
    return result


def validate_index(manifest: dict, receipts: dict[str, str]) -> None:
    """Require the published version index to contain only the two verified images."""
    require(manifest.get("mediaType") in MANIFEST_TYPES[:2], "Published image is not an index")
    descriptors = manifest.get("manifests", [])
    require(len(descriptors) == 2, "Published index must contain exactly two images")
    actual = {}
    for descriptor in descriptors:
        platform = descriptor.get("platform", {})
        require(platform.get("os") == "linux", "Published index contains a non-Linux image")
        architecture = platform.get("architecture")
        require(architecture not in actual, "Published index repeats an architecture")
        actual[architecture] = digest(descriptor["digest"])
    require(actual == receipts, "Published index does not match validated native receipts")


def parser() -> argparse.ArgumentParser:
    """Expose the fixed publication gates without arbitrary image or repository inputs."""
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    identity = commands.add_parser("guard")
    identity.add_argument("--sha")
    identity.add_argument("--release-id")
    commands.add_parser("absent").add_argument("--docker-config", type=Path, required=True)
    for name in ("receipt", "sources", "index"):
        command = commands.add_parser(name)
        command.add_argument("--sha", required=True)
        command.add_argument("--run-id", required=True)
        command.add_argument("--attempt", required=True)
        if name == "receipt":
            command.add_argument("--architecture", choices=ARCHITECTURES, required=True)
            command.add_argument("--platform", required=True)
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--receipts", type=Path, required=True)
    return result


def execute(args: argparse.Namespace) -> None:
    """Route one explicit publication gate."""
    if args.command == "guard":
        guard(args.sha, args.release_id)
    elif args.command == "absent":
        require_absent(args.docker_config)
    elif args.command == "receipt":
        write_receipt(args)
    else:
        receipts = read_receipts(args.receipts, args.sha, args.run_id, args.attempt)
        if args.command == "sources":
            for architecture in ARCHITECTURES:
                print(f"{IMAGE}@{receipts[architecture]}")
        else:
            validate_index(json.load(sys.stdin), receipts)
            print("Published index matches both validated native image receipts")


def main() -> int:
    """Exit visibly on failed identity, registry, receipt or index validation."""
    arguments = parser()
    try:
        execute(arguments.parse_args())
    except ValueError as error:
        arguments.exit(1, f"Image publication gate failed: {error}\n")
    except (KeyError, TypeError, OSError, urllib.error.URLError):
        arguments.exit(1, "Image publication gate failed: metadata unavailable or malformed\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
