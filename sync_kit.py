"""Copy vaultsoft_kit modules into an app repository.

    python sync_kit.py <dest> safe_delete [more modules...]
    python sync_kit.py --check <dest>

<dest> is the folder that will hold the vendored `vaultsoft_kit` package, for example
`vaultsoft_hub/_vendor` in VaultSoft Hub. The copy always includes `__init__.py`, plus a
KIT_VERSION.json recording the kit version, the kit commit and each file's hash.

Refuses to sync from a kit checkout with uncommitted changes, so every vendored copy
can be traced to a real kit commit.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

KIT_ROOT = Path(__file__).resolve().parent
PACKAGE = KIT_ROOT / "vaultsoft_kit"
sys.path.insert(0, str(KIT_ROOT))

from vaultsoft_kit import KIT_VERSION, MANIFEST_NAME, file_digest, vendored_drift  # noqa: E402


def kit_commit() -> str:
    status = subprocess.run(["git", "status", "--porcelain", "--", "vaultsoft_kit"],
                            cwd=KIT_ROOT, capture_output=True, text=True, check=True).stdout
    if status.strip():
        raise SystemExit("vaultsoft_kit has uncommitted changes; commit them before syncing.")
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=KIT_ROOT,
                          capture_output=True, text=True, check=True).stdout.strip()


def sync(dest: Path, modules: list[str], commit: str) -> Path:
    names = ["__init__.py"] + [f"{m}.py" for m in modules]
    for name in names:
        if not (PACKAGE / name).is_file():
            raise SystemExit(f"Unknown kit module: {name[:-3]}")
    target = dest / "vaultsoft_kit"
    if target.exists():
        for old in target.glob("*.py"):
            old.unlink()
    target.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copyfile(PACKAGE / name, target / name)
    manifest = {
        "kit_version": KIT_VERSION,
        "kit_commit": commit,
        "modules": modules,
        "files": {name: file_digest(target / name) for name in names},
    }
    (target / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="only verify an existing vendored copy")
    parser.add_argument("dest", type=Path)
    parser.add_argument("modules", nargs="*")
    args = parser.parse_args(argv)

    if args.check:
        problems = vendored_drift(args.dest / "vaultsoft_kit")
        for p in problems:
            print(p)
        print("vendored kit OK" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0

    if not args.modules:
        parser.error("name at least one module to vendor, e.g. safe_delete")
    target = sync(args.dest, args.modules, kit_commit())
    print(f"Vendored {', '.join(args.modules)} into {target} (kit {KIT_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
