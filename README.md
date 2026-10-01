# vaultsoft-kit

Shared code for VaultSoft's Windows apps, copied ("vendored") into each app's repository
by `sync_kit.py`. Each app records the kit commit and file hashes it was built from, and
its tests fail if the copy is edited by hand.

There is no package to install. Apps import their vendored copy.

## Modules

| Module | What it does | Origin |
|---|---|---|
| `safe_delete` | Validates cleanup paths against approved roots and protected folders, refuses junctions/symlinks anywhere in the path or inside a folder being deleted, and reports blocked items instead of deleting them. | Moved unchanged from SweptPC v1.0.2 (`cleanup_safety.py`) |

## Vendoring into an app

```
python sync_kit.py <app>/<package>/_vendor safe_delete
python sync_kit.py --check <app>/<package>/_vendor
```

The app's tests should call `vaultsoft_kit.vendored_drift()` on its copy so a hand edit fails CI.
Run this repo's tests on Windows: `python -m unittest discover -s tests -v`.
