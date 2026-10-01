"""Stage verified public assets for the pinned Diff Gremlin release."""

import argparse
import hashlib
import re
import shutil
import zipfile
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0"
ASSETS = (
    "diff_gremlin/analyzers/java/assets/StructureProbe.java",
    "diff_gremlin/analyzers/javascript/assets/lint.cjs",
    "diff_gremlin/analyzers/javascript/assets/complexity.cjs",
    "diff_gremlin/analyzers/javascript/assets/types.cjs",
    "diff_gremlin/analyzers/javascript/assets/execution.cjs",
    "diff_gremlin/analyzers/javascript/assets/duplication.cjs",
    "diff_gremlin/analyzers/assets/gitleaks-v8.30.1.toml",
    "diff_gremlin/analyzers/assets/GITLEAKS-LICENSE",
    "diff_gremlin/analyzers/shell/assets/schema.json",
    "diff_gremlin/analyzers/shell/assets/operators.json",
    "diff_gremlin/analyzers/shell/assets/SHFMT-LICENSE",
)


def digest(path: Path) -> str:
    """Hash one release asset."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_wheel(path: Path) -> None:
    """Require the pinned package identity and shipped analyzer data."""
    if path.name != f"diff_gremlin-{VERSION}-py3-none-any.whl":
        raise ValueError(f"Expected diff_gremlin-{VERSION}-py3-none-any.whl")
    with zipfile.ZipFile(path) as archive:
        metadata = BytesParser().parsebytes(
            archive.read(f"diff_gremlin-{VERSION}.dist-info/METADATA")
        )
        if metadata["Name"] != "diff-gremlin" or metadata["Version"] != VERSION:
            raise ValueError(
                "Wheel metadata does not match the pinned release identity"
            )
        for name in ASSETS:
            if not archive.read(name):
                raise ValueError(f"Wheel has an empty required analyzer asset: {name}")
        entry_points = archive.read(
            f"diff_gremlin-{VERSION}.dist-info/entry_points.txt"
        )
        if b"diff-gremlin = diff_gremlin.cli.main:main" not in entry_points:
            raise ValueError("Wheel is missing the diff-gremlin console entry point")
        if not any(name.endswith("/licenses/LICENSE") for name in archive.namelist()):
            raise ValueError("Wheel is missing the project MIT license")


def finalized_installer(wheel: Path) -> str:
    """Fill only the release wheel checksum after validating helper pins."""
    installer = (ROOT / "install.sh").read_text()
    pins = {
        "CORE_LOCK_SHA256": ROOT / "toolchain/python/core-requirements.txt",
        "FULL_LOCK_SHA256": ROOT / "toolchain/python/full-requirements.txt",
        "GITLEAKS_SCRIPT_SHA256": ROOT / "scripts/provision_gitleaks.py",
        "SHFMT_SCRIPT_SHA256": ROOT / "scripts/provision_shfmt.py",
        "DOWNLOAD_SCRIPT_SHA256": ROOT / "scripts/download_asset.py",
    }
    for name, path in pins.items():
        if f"{name}={digest(path)}" not in installer:
            raise ValueError(
                f"Installer {name} does not match {path.relative_to(ROOT)}"
            )
    return re.sub(
        r"(?m)^RELEASE_WHEEL_SHA256=.*$",
        f"RELEASE_WHEEL_SHA256={digest(wheel)}",
        installer,
    )


def stage_release(wheel: Path, destination: Path) -> None:
    """Copy reviewed release bytes into one new staging directory."""
    verify_wheel(wheel)
    installer = finalized_installer(wheel)
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(wheel, destination / wheel.name)
    for source in (
        ROOT / "toolchain/python/core-requirements.txt",
        ROOT / "toolchain/python/full-requirements.txt",
        ROOT / "scripts/provision_gitleaks.py",
        ROOT / "scripts/provision_shfmt.py",
        ROOT / "scripts/download_asset.py",
    ):
        shutil.copyfile(source, destination / source.name)
    (destination / "install.sh").write_text(installer)
    sums = [f"{digest(path)}  {path.name}" for path in sorted(destination.iterdir())]
    (destination / "SHA256SUMS").write_text("\n".join(sums) + "\n")


def main() -> int:
    """Expose release staging without any publication side effects."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--out", type=Path, default=ROOT / "dist/release")
    args = parser.parse_args()
    try:
        stage_release(args.wheel, args.out)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(1, f"Release staging failed: {error}\n")
    print(f"Staged verified release assets: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
