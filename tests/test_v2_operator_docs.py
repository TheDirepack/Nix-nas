"""Guard operator documentation against retired V1 capability instructions.

V2's service seed declares capability IDs, Authentik owns assignments, and
Caddy checks application.<service>.<capability> groups. Keep user instructions
aligned with that contract as it evolves.
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "src"

CAPABILITY_DOCS = {
    "permissions.md",
    "admin/authentik.md",
    "admin/accounts.md",
    "users/applications.md",
}
EXPECTED_DEFAULT_GROUPS = {
    "application.copyparty.files",
    "application.copyparty.webdav",
    "application.syncthing.access",
    "application.vaultwarden.access",
}


class V2OperatorDocumentationTests(unittest.TestCase):
    def test_default_group_examples_match_seed(self) -> None:
        seed = (ROOT / "modules/nas/config/managed-services-seed-v2.nix").read_text()
        # The seed declares per-service IDs and capability IDs, and the
        # compiler constructs canonical application.<service>.<capability>.
        for service, capabilities in {
            "copyparty": ("files", "webdav"),
            "syncthing": ("access",),
            "vaultwarden": ("access",),
        }.items():
            with self.subTest(service=service):
                self.assertRegex(seed, rf"\b{re.escape(service)}\s*= ")
                for capability in capabilities:
                    self.assertIn(f'(capability "{capability}"', seed)

        for path in sorted(CAPABILITY_DOCS):
            text = (DOC / path).read_text()
            with self.subTest(path=path):
                for group in sorted(EXPECTED_DEFAULT_GROUPS):
                    self.assertIn(group, text)

    def test_no_retired_group_is_recommended(self) -> None:
        # Historical mentions explaining that these groups are retired are
        # fine; actionable grants, ACLs, and CLI examples are not.
        unsafe = re.compile(
            r"(?:--group\s+nas_(?:allow|deny)_"
            r"|(?:^|\n)\s*[-|]\s*`nas_(?:allow|deny)_"
            r"|@nas_(?:allow|deny)_"
            r"|\$\{u%\+nas_(?:allow|deny)_)"
        )
        for path in (
            *CAPABILITY_DOCS,
            "admin/copyparty.md",
            "reference/interfaces.md",
        ):
            with self.subTest(path=path):
                text = (DOC / path).read_text()
                self.assertIsNone(unsafe.search(text), f"retired grant instruction in {path}")

    def test_account_cli_uses_only_reserved_identity_roles(self) -> None:
        accounts = (DOC / "admin/accounts.md").read_text()
        self.assertIn("--group nas_users", accounts)
        self.assertNotRegex(accounts, r"--group\s+application\.")
        self.assertIn("Authentik", accounts)

    def test_first_start_has_no_retired_controller_dependency(self) -> None:
        first_run = (DOC / "admin/first-run.md").read_text()
        self.assertNotIn("or the feature controller", first_run)


if __name__ == "__main__":
    unittest.main()
