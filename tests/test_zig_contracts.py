"""Structural gates for the Zig KeePass tools (coverage.py cannot measure Zig)."""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIG = ROOT / "zig"
SRC = ZIG / "src"
NOT_TEST_ROOTS = {"tests.zig", "lib.zig", "tx_harness.zig"}


class ZigContractTests(unittest.TestCase):
    def test_every_module_is_in_the_leak_checked_test_root(self) -> None:
        root = (SRC / "tests.zig").read_text(encoding="utf-8")
        for path in sorted(SRC.glob("*.zig")):
            if path.name in NOT_TEST_ROOTS:
                continue
            with self.subTest(module=path.name):
                self.assertIn(f'_ = @import("{path.name}");', root)

    def test_untrusted_input_parsers_are_fuzzed(self) -> None:
        for name, minimum in (("unlock_http.zig", 2), ("validate.zig", 4), ("secret.zig", 1)):
            with self.subTest(module=name):
                source = (SRC / name).read_text(encoding="utf-8")
                self.assertGreaterEqual(source.count("testing.fuzz("), minimum)

    def test_every_compile_error_snippet_is_checked(self) -> None:
        build = (ZIG / "build.zig").read_text(encoding="utf-8")
        for path in sorted((ZIG / "tests" / "compile_errors").glob("*.zig")):
            with self.subTest(snippet=path.name):
                self.assertIn(f'"tests/compile_errors/{path.name}"', build)

    def test_toolchain_pin_is_consistent(self) -> None:
        zon = (ZIG / "build.zig.zon").read_text(encoding="utf-8")
        nix = (ROOT / "modules/nas/internal/zig-toolchain.nix").read_text(encoding="utf-8")
        minimum = re.search(r'\.minimum_zig_version = "([^"]+)"', zon)
        pinned = re.search(r'version = "([^"]+)";', nix)
        assert minimum is not None and pinned is not None
        self.assertEqual(minimum.group(1), pinned.group(1))
        self.assertRegex(nix, r'hash = "sha256-[A-Za-z0-9+/]{43}=";')
        self.assertIn(".dependencies = .{},", zon, "no third-party Zig packages")

    def test_nix_config_names_every_required_field(self) -> None:
        config = (SRC / "config.zig").read_text(encoding="utf-8")
        body = config[config.index("pub const Config = struct {") : config.index("pub const value: Config")]
        required = [
            name for name, default in re.findall(r"^    ([a-z_]+): [^=\n]+?(=[^,\n]+)?,$", body, re.M) if not default
        ]
        nix = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        for field in required:
            with self.subTest(field=field):
                self.assertRegex(nix, rf"\n    {field} = ")
        self.assertIn('"-Dcpu=baseline"', nix)
        self.assertIn("zig build compile-errors", nix)

    def test_test_hooks_are_comptime_gated(self) -> None:
        for name in ("unlock_api.zig", "config.zig"):
            source = (SRC / name).read_text(encoding="utf-8")
            for hook in re.findall(r'"(NAS_[A-Z_]*TEST[A-Z_]*)"', source):
                with self.subTest(module=name, hook=hook):
                    index = source.index(f'"{hook}"')
                    window = source[max(0, index - 400) : index]
                    self.assertIn("build_options.test_harness", window)


if __name__ == "__main__":
    unittest.main()
