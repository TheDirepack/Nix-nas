"""Go module tooling: the vendorHash calculator and the Nix packaging pin."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_vendor_hash():
    spec = importlib.util.spec_from_file_location("go_vendor_hash", ROOT / "scripts/go-vendor-hash.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GoToolingTests(unittest.TestCase):
    def test_nar_hash_matches_nix_hash_for_files_executables_symlinks_and_directories(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tree = pathlib.Path(raw) / "tree"
            (tree / "d").mkdir(parents=True)
            (tree / "a").write_text("x", encoding="utf-8")
            (tree / "b").write_text("#!/bin/sh\n", encoding="utf-8")
            (tree / "a").chmod(0o644)
            (tree / "b").chmod(0o755)
            (tree / "c").symlink_to("a")
            (tree / "d/e").write_text("nested\n", encoding="utf-8")
            (tree / "d/e").chmod(0o644)
            # Reference value from `nix-hash --type sha256 --sri`.
            self.assertEqual(load_vendor_hash().nar_sri(tree), "sha256-lnFXrlb4WW4VrV7D3Wg1RRMqFd6ZC1bmlzSGIc/FmTs=")

    def test_nix_packaging_pins_a_vendor_hash_and_the_go_entry_points(self) -> None:
        nix = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        self.assertRegex(nix, r'vendorHash = "sha256-[A-Za-z0-9+/]{43}=";')
        for command in sorted(os.listdir(ROOT / "go/cmd")):
            self.assertIn(f'"cmd/{command}"', nix)

    def test_go_module_targets_the_pinned_nix_toolchain(self) -> None:
        mod = (ROOT / "go/go.mod").read_text(encoding="utf-8")
        language = re.search(r"^go (\d+)\.(\d+)", mod, re.MULTILINE)
        assert language is not None
        self.assertLessEqual((int(language.group(1)), int(language.group(2))), (1, 26))
        self.assertRegex(mod, r"(?m)^toolchain go1\.27\.\d+$")


if __name__ == "__main__":
    unittest.main()
