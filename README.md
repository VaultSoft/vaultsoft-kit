# vaultsoft-kit

Shared code for VaultSoft's Windows apps, copied ("vendored") into each app's repository
by `sync_kit.py`. Each app records the kit commit and file hashes it was built from, and
its tests fail if the copy is edited by hand.

There is no package to install. Apps import their vendored copy.
