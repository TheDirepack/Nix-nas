from __future__ import annotations

import unittest

from repo_test_utils import text


class V2PythonContextTests(unittest.TestCase):
    def test_development_shell_can_import_the_xml_runtime(self) -> None:
        shell = text("flake.nix").split("devShells.x86_64-linux.test =", 1)[1].split("shellHook", 1)[0]
        self.assertIn("defusedxml", shell)

    def test_source_path_is_declared_only_in_shared_context(self) -> None:
        self.assertIn("v2Source = ../../../services;", text("modules/nas/internal/v2-tools.nix"))
        for module in (
            "managed-services",
            "managed-services-transactions",
            "managed-services-authentik-blueprint",
            "managed-services-seed-v2",
            "storage-monitoring",
        ):
            with self.subTest(module=module):
                source = text(f"modules/nas/config/{module}.nix")
                self.assertIn("v2Source = nasInternal.v2Source;", source)
                self.assertNotIn("v2Source = ../../../services;", source)

    def test_seed_and_runtime_share_xml_capable_interpreter(self) -> None:
        for module in ("managed-services", "managed-services-transactions", "managed-services-seed-v2"):
            with self.subTest(module=module):
                self.assertIn("v2Python = nasInternal.v2PythonXml;", text(f"modules/nas/config/{module}.nix"))
        self.assertIn(
            "v2Python = nasInternal.v2PythonCore;", text("modules/nas/config/managed-services-authentik-blueprint.nix")
        )
