"""Shared code for VaultSoft apps.

Apps never install this package: `sync_kit.py` copies the modules an app needs into
that app's repository, together with a KIT_VERSION.json that records the kit commit and
a hash of every copied file. `vendored_drift()` lets the app's own tests prove the copy
hasn't been edited by hand.

Modules:
    safe_delete  - path validation and deletion that never follows junctions or
                   symlinks (moved unchanged from SweptPC v1.0.2's cleanup_safety.py)
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

KIT_VERSION = "0.1.0"
MANIFEST_NAME = "KIT_VERSION.json"


def file_digest(path: Path) -> str:
    """SHA-256 of a text file with line endings normalised to LF.

    App repos check files out with CRLF on Windows (core.autocrlf), so hashing raw
    bytes would report drift that isn't there.
    """
    data = Path(path).read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def vendored_drift(vendor_dir: str | Path) -> list[str]:
    """Problems with a vendored copy of the kit; an empty list means it matches.

    `vendor_dir` is the vendored `vaultsoft_kit` folder inside an app.
    """
    vendor_dir = Path(vendor_dir)
    manifest_path = vendor_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        return [f"missing {MANIFEST_NAME}"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems = []
    expected = manifest.get("files", {})
    for name, digest in sorted(expected.items()):
        target = vendor_dir / name
        if not target.is_file():
            problems.append(f"missing {name}")
        elif file_digest(target) != digest:
            problems.append(f"{name} differs from kit {manifest.get('kit_commit', '?')[:7]}")
    for extra in sorted(p.name for p in vendor_dir.glob("*.py")):
        if extra not in expected:
            problems.append(f"{extra} is not part of the kit")
    return problems
