import json
import tempfile
import unittest
from pathlib import Path

import sync_kit
from vaultsoft_kit import MANIFEST_NAME, vendored_drift


class SyncKitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dest = Path(self.tmp.name) / "_vendor"

    def test_sync_copies_modules_and_records_hashes(self):
        target = sync_kit.sync(self.dest, ["safe_delete"], "a" * 40)

        self.assertTrue((target / "__init__.py").is_file())
        self.assertTrue((target / "safe_delete.py").is_file())
        manifest = json.loads((target / MANIFEST_NAME).read_text(encoding="utf-8"))
        self.assertEqual("a" * 40, manifest["kit_commit"])
        self.assertEqual(["safe_delete"], manifest["modules"])
        self.assertEqual({"__init__.py", "safe_delete.py"}, set(manifest["files"]))
        self.assertEqual([], vendored_drift(target))

    def test_crlf_checkout_is_not_drift(self):
        target = sync_kit.sync(self.dest, ["safe_delete"], "b" * 40)
        module = target / "safe_delete.py"
        module.write_bytes(module.read_bytes().replace(b"\n", b"\r\n"))

        self.assertEqual([], vendored_drift(target))

    def test_hand_edit_is_drift(self):
        target = sync_kit.sync(self.dest, ["safe_delete"], "c" * 40)
        with open(target / "safe_delete.py", "a", encoding="utf-8") as f:
            f.write("\n# local tweak\n")

        self.assertEqual(["safe_delete.py differs from kit ccccccc"], vendored_drift(target))

    def test_missing_and_extra_files_are_drift(self):
        target = sync_kit.sync(self.dest, ["safe_delete"], "d" * 40)
        (target / "safe_delete.py").unlink()
        (target / "extra.py").write_text("x = 1\n", encoding="utf-8")

        self.assertEqual(["missing safe_delete.py", "extra.py is not part of the kit"], vendored_drift(target))

    def test_resync_removes_modules_no_longer_requested(self):
        target = sync_kit.sync(self.dest, ["safe_delete"], "e" * 40)
        (target / "stale.py").write_text("x = 1\n", encoding="utf-8")
        sync_kit.sync(self.dest, ["safe_delete"], "f" * 40)

        self.assertFalse((target / "stale.py").exists())

    def test_unknown_module_is_refused(self):
        with self.assertRaises(SystemExit):
            sync_kit.sync(self.dest, ["no_such_module"], "0" * 40)


if __name__ == "__main__":
    unittest.main()
