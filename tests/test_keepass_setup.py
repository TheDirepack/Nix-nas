"""Black-box tests of `nas-keepass-setup` against Python reference implementations.

The verifier must stay byte-compatible with journals written by the former
Python implementation, so the expected digests here are computed with
hashlib from the same canonical JSON.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from keepass_fakes import FAKE, KeePassCall, KeePassLog  # noqa: E402
from zig_binaries import release_bin_dir  # noqa: E402

ALGORITHM = "scrypt-n32768-r8-p1"


def binary() -> str:
    return str(release_bin_dir() / "nas-keepass-setup")


def fields(*parts: str) -> bytes:
    return b"".join(part.encode("utf-8") + b"\0" for part in parts)


def reference_digest(keepass: str, accounts: list[tuple[str, str]], salt: bytes) -> str:
    material = json.dumps({"keepass": keepass, "accounts": sorted(accounts)}, sort_keys=True, separators=(",", ":"))
    return hashlib.scrypt(
        material.encode("utf-8"), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32
    ).hex()


def run(*args: str, stdin: bytes = b"", env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([binary(), *args], input=stdin, capture_output=True, timeout=60, check=False, env=env)


class VerifierTests(unittest.TestCase):
    KEEPASS = 'keepass passphrase ßé \U0001f600 "quoted" \\ back'
    ACCOUNTS = [("nasadmin", "admin-password"), ("éve", "päss"), ("alice", "x\ty")]

    def plan(self, keepass: str | None = None, accounts: list[tuple[str, str]] | None = None) -> list[str]:
        out = [self.KEEPASS if keepass is None else keepass]
        for username, password in self.ACCOUNTS if accounts is None else accounts:
            out.extend((username, password))
        return out

    def test_created_verifier_matches_the_reference_digest(self) -> None:
        completed = run("verifier-create", stdin=fields(*self.plan()))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        verifier = json.loads(completed.stdout)
        self.assertEqual(set(verifier), {"algorithm", "digest", "salt"})
        self.assertEqual(verifier["algorithm"], ALGORITHM)
        expected = reference_digest(self.KEEPASS, self.ACCOUNTS, bytes.fromhex(verifier["salt"]))
        self.assertEqual(verifier["digest"], expected)
        self.assertNotIn(self.KEEPASS.encode(), completed.stdout)

    def test_reference_verifier_is_accepted_and_changes_are_rejected(self) -> None:
        salt = os.urandom(16)
        digest = reference_digest(self.KEEPASS, self.ACCOUNTS, salt)
        header = (ALGORITHM, salt.hex(), digest)
        self.assertEqual(run("verifier-match", stdin=fields(*header, *self.plan())).returncode, 0)
        self.assertEqual(run("verifier-match", stdin=fields(*header, *self.plan(keepass="other"))).returncode, 1)
        changed = [("nasadmin", "different")]
        self.assertEqual(run("verifier-match", stdin=fields(*header, *self.plan(accounts=changed))).returncode, 1)
        for broken in (
            (ALGORITHM, "zz" * 16, digest),
            ("sha256", salt.hex(), digest),
            (ALGORITHM, salt.hex(), "0" * 64),
        ):
            with self.subTest(broken=broken[:2]):
                self.assertEqual(run("verifier-match", stdin=fields(*broken, *self.plan())).returncode, 1)

    def test_legacy_authenticators_match_the_reference(self) -> None:
        completed = run("legacy-authenticators", stdin=fields(*self.plan()))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        key = hashlib.sha256(b"nixos-nas/setup-password-fingerprint/v2\0" + self.KEEPASS.encode()).digest()
        expected = {
            username: hmac.new(key, username.encode() + b"\0" + password.encode(), hashlib.sha256).hexdigest()
            for username, password in sorted(self.ACCOUNTS)
        }
        self.assertEqual(json.loads(completed.stdout), expected)

    def test_malformed_field_streams_are_refused(self) -> None:
        for stdin in (b"", b"unterminated", fields("keepass", "lonely-user")):
            with self.subTest(stdin=stdin[:20]):
                completed = run("verifier-create", stdin=stdin)
                self.assertEqual(completed.returncode, 2)
                self.assertTrue(completed.stderr.strip())


class StrengthTests(unittest.TestCase):
    def check(self, password: str, administrator: str | None = None) -> subprocess.CompletedProcess[bytes]:
        stdin = (password + "\n").encode()
        args = ["check-strength"]
        if administrator is not None:
            stdin += (administrator + "\n").encode()
            args.append("--with-administrator")
        return run(*args, stdin=stdin)

    def test_floor(self) -> None:
        self.assertEqual(self.check("correct horse battery staple").returncode, 0)
        for weak, message in (
            ("short-pass", b"at least 16 characters"),
            ("aaaaabbbbbaaaaabbbbb", b"at least 6 different characters"),
            ("é" * 15, b"at least 16 characters"),
        ):
            with self.subTest(weak=weak):
                completed = self.check(weak)
                self.assertEqual(completed.returncode, 2)
                self.assertIn(message, completed.stderr)
                self.assertNotIn(weak.encode(), completed.stderr)

    def test_administrator_comparison_uses_full_case_folding(self) -> None:
        base = "Correct-Horse-Battery-"
        for administrator_suffix, password_suffix in (("STRASSE", "straße"), ("Kelvin", "kelvin"), ("Σσ", "σς")):
            administrator, password = base + administrator_suffix, base.lower() + password_suffix
            self.assertEqual(administrator.casefold(), password.casefold())
            with self.subTest(administrator=administrator):
                completed = self.check(password, administrator)
                self.assertEqual(completed.returncode, 2)
                self.assertIn(b"differ from the administrator password", completed.stderr)
        self.assertEqual(self.check("correct horse battery staple", "another administrator").returncode, 0)


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        cli = self.root / "keepassxc-cli"
        cli.write_text(FAKE, encoding="utf-8")
        cli.chmod(0o755)
        self.log = self.root / "calls.jsonl"
        self.env = {
            "PATH": f"{self.root}:{os.environ.get('PATH', '')}",
            "FAKE_KP_LOG": str(self.log),
            "FAKE_KP_OPENS": "1",
        }
        self.database = self.root / "NAS.kdbx"

    def calls(self) -> list[KeePassCall]:
        return KeePassLog(self.log).calls()

    def database_cmd(self, mode: str, *extra: str, opens: bool = True) -> subprocess.CompletedProcess[bytes]:
        env = {**self.env, "FAKE_KP_OPENS": "1" if opens else "0"}
        return run("database", mode, "--database", str(self.database), *extra, stdin=b"kdbx-s3cret\n", env=env)

    def test_encrypted_dataset_database_is_never_replaced(self) -> None:
        self.database.write_text("holds zfs key")
        refused = self.database_cmd("create", "--managed-dataset", "encrypted", opens=False)
        self.assertEqual(refused.returncode, 2)
        self.assertIn(b"never replaces that database", refused.stderr)
        self.assertEqual(self.database.read_text(), "holds zfs key")
        self.assertFalse(list(self.root.glob("NAS.kdbx.replaced-*")))
        self.assertFalse([c for c in self.calls() if c["argv"][0] == "db-create"])
        kept = self.database_cmd("create", "--managed-dataset", "encrypted")
        self.assertEqual(kept.stdout.strip(), b"existing")

    def test_plain_dataset_database_is_moved_aside_with_no_clobber(self) -> None:
        self.database.write_text("old")
        created = self.database_cmd("create", "--managed-dataset", "plain")
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertEqual(created.stdout.strip().splitlines()[-1], b"created")
        (preserved,) = self.root.glob("NAS.kdbx.replaced-*")
        self.assertEqual(preserved.read_text(), "old")
        self.assertEqual(self.database.read_text(), "fresh")
        create = next(c for c in self.calls() if c["argv"][0] == "db-create")
        argv = list(create["argv"])  # type: ignore[arg-type]
        self.assertEqual(argv[argv.index("--decryption-time") + 1], "1000")
        self.assertEqual(create["stdin"], "kdbx-s3cret\nkdbx-s3cret\n")
        self.assertNotIn("kdbx-s3cret", " ".join(argv))

    def test_unknown_dataset_state_defaults_to_encrypted(self) -> None:
        self.database.write_text("old")
        refused = self.database_cmd("create", opens=False)
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(self.database.read_text(), "old")

    def test_symlinks_and_missing_databases(self) -> None:
        self.database.symlink_to(self.root / "elsewhere")
        refused = self.database_cmd("create", "--managed-dataset", "plain")
        self.assertIn(b"not a regular file", refused.stderr)
        self.database.unlink()
        missing = self.database_cmd("verify")
        self.assertIn(b"does not exist", missing.stderr)

    def test_usage_and_help(self) -> None:
        self.assertEqual(run("--help").returncode, 0)
        self.assertEqual(run("--fuzz-x").returncode, 2)
        self.assertEqual(run("database", "create", "--database", "relative.kdbx").returncode, 2)


if __name__ == "__main__":
    unittest.main()
