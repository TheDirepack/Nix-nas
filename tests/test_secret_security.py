"""Secret-handling contracts of the Zig KeePass tools.

Behaviour is exercised black-box against `nas-secrets` (see test_nas_secrets);
the structural checks pin the type-level guarantees that make the shell-era
ordering rules compile-time facts.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIG = ROOT / "zig" / "src"
SECRET_TOOLS = ROOT / "modules/nas/internal/secret-tools.nix"
MAINTENANCE_TOOLS = ROOT / "modules/nas/internal/maintenance-tools.nix"

sys.path.insert(0, str(ROOT / "tests"))

from test_nas_secrets import PASSWORD, SECRET_ROOT, Appliance  # noqa: E402


def zig(name: str) -> str:
    return (ZIG / name).read_text(encoding="utf-8")


def zig_sources() -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(ZIG.glob("*.zig"))}


class SecretTypeContractTests(unittest.TestCase):
    def test_secret_cannot_be_formatted_serialised_or_named(self) -> None:
        source = zig("secret.zig")
        self.assertIn('@compileError("nas: a Secret cannot be formatted', source)
        self.assertIn('@compileError("nas: a Secret cannot be serialised")', source)
        self.assertRegex(source, r"pub const Secret = struct \{\n    handle: \*anyopaque,")
        self.assertIn("std.crypto.secureZero(u8, memory);", source)

    def test_secret_bytes_are_only_reachable_inside_the_secret_module(self) -> None:
        for name, source in zig_sources().items():
            if name == "secret.zig":
                continue
            with self.subTest(file=name):
                self.assertNotRegex(source, r"\.handle\b(?!\()", "only secret.zig may touch a Secret's handle")
                self.assertNotRegex(source, r"\bBox\b")

    def test_guarded_types_are_built_only_by_their_constructors(self) -> None:
        guarded = ("StrongKeePassPassword", "AdminSession", "UnlockRequest", "AbsSocketPath", "UnitName", "TargetName")
        owners = {"validate.zig", "unlock_http.zig", "command.zig"}
        for name, source in zig_sources().items():
            if name in owners:
                continue
            for type_name in guarded:
                with self.subTest(file=name, type=type_name):
                    self.assertNotRegex(
                        source, rf"(?<!\])\b{type_name}\{{", f"{type_name} must come from its constructor"
                    )

    def test_argv_rejects_secret_types_and_sudo_takes_no_payload(self) -> None:
        source = zig("command.zig")
        self.assertIn("carries secret material and can never be a command-line argument", source)
        self.assertRegex(source, r"pub fn privileged\(self: Runner, args: anytype, options: Options\)")
        self.assertIn("return self.spawnCollect(full.slice(), null, options, self.gpa);", source)

    def test_no_secret_flag_or_tracing_remains(self) -> None:
        for name, source in [*zig_sources().items(), ("secret-tools.nix", SECRET_TOOLS.read_text(encoding="utf-8"))]:
            with self.subTest(file=name):
                self.assertNotIn("--pw-stdin", source)
                self.assertNotIn("set -x", source)

    def test_optional_service_secrets_are_compiled_only_when_enabled(self) -> None:
        source = zig("nas_secrets.zig")
        for feature in ("grafana", "ntfy", "nut_webgui", "zfs_encryption", "vaultwarden"):
            with self.subTest(feature=feature):
                self.assertIn(f"if (comptime cfg.features.{feature})", source)
        nix = SECRET_TOOLS.read_text(encoding="utf-8")
        self.assertIn("ntfy = cfg.observability.ntfy.enable;", nix)
        self.assertIn("vaultwarden = cfg.vaultwarden.enable;", nix)

    def test_staged_files_are_private_and_installed_owner_read_only(self) -> None:
        secret_source = zig("secret.zig")
        self.assertIn(".CREAT = true, .EXCL = true, .NOFOLLOW = true }, 0o600", secret_source)
        source = zig("nas_secrets.zig")
        self.assertIn('cfg.tools.install, "-m", "0400", "-o", owner, "-g", group, "--", source, target', source)
        self.assertIn('"-m", "0400", "-o", "root", "-g", "root", "/dev/null"', source)
        self.assertIn("Refusing to install a non-regular or symlink secret source", source)

    def test_keepass_delete_failures_are_not_silently_ignored(self) -> None:
        source = zig("keepass.zig")
        block = source[source.index("pub fn remove(") : source.index("pub fn get(")]
        self.assertIn("Unable to remove KeePassXC entry", block)
        self.assertIn("return error.KeePassFailed;", block)

    def test_ntfy_curl_credentials_stay_in_private_config_not_argv(self) -> None:
        source = MAINTENANCE_TOOLS.read_text(encoding="utf-8")
        self.assertIn('curl_config="$(mktemp /run/nas-alert-curl.XXXXXX)"', source)
        self.assertIn('chmod 0600 "$curl_config"', source)
        self.assertIn('user = "admin:$password"', source)
        self.assertNotIn('--user "admin:$password"', source)
        self.assertNotIn('-u "admin:$password"', source)


class AuthentikActivationModeTests(unittest.TestCase):
    """Ordering rules expressed as witness types rather than text positions."""

    def test_post_setup_operations_require_witnesses(self) -> None:
        source = zig("nas_secrets.zig")
        self.assertIn("fn linkUnlockedEnvironment(app: *App, post: PostSetup) Exit!void", source)
        self.assertIn(
            "fn installBootOutpostToken(app: *App, post: PostSetup, committed: transaction.Committed, have_outpost: bool) Exit!void",
            source,
        )
        self.assertIn(
            "fn retireBootEnvironment(app: *App, post: PostSetup, rotated: Rotated, committed: transaction.Committed) Exit!void",
            source,
        )
        modes = zig("modes.zig")
        self.assertIn(".setup => void,", modes, "setup activations cannot hold a PostSetup witness")

    def test_keepass_environment_is_linked_before_authentik_restarts_the_target(self) -> None:
        source = zig("nas_secrets.zig")
        body = source[source.index("fn bringUp(") :]
        link = body.index("linkUnlockedEnvironment(app, post)")
        restart = body.index('"try-restart", "authentik-worker.service", "authentik.service"')
        target = body.index('"start", "nas-protected-services.target"')
        setup = body.index(".setup => {")
        self.assertLess(link, setup)
        self.assertLess(link, restart)
        self.assertLess(restart, target)

    def test_first_boot_key_is_rotated_before_it_is_read(self) -> None:
        source = zig("nas_secrets.zig")
        body = source[source.index("fn prepare(") :]
        self.assertLess(body.index("rotateAuthentikKey(app, db, post)"), body.index('db.get(.@"authentik-secret-key")'))
        rotation = source[source.index("fn rotateAuthentikKey(") : source.index("fn linkUnlockedEnvironment(")]
        self.assertIn('app.rootTest("-L", app.paths.authentik_runtime_environment_file)', rotation)
        self.assertLess(rotation.index("db.store("), rotation.index("cfg.tools.chown"))
        self.assertLess(rotation.index("cfg.tools.chown"), rotation.index("cfg.tools.chmod"))

    def test_superuser_token_is_removed_only_after_the_outpost_token_is_installed(self) -> None:
        source = zig("nas_secrets.zig")
        block = source[source.index("fn installBootOutpostToken(") : source.index("fn retireBootEnvironment(")]
        self.assertLess(
            block.index('"0400", "-o", "root", "-g", "root", source, boot_token'), block.index('"/api-token"')
        )
        self.assertIn("if (!installed) {", block)


class HostileKeePassValueTests(unittest.TestCase):
    """Values that could inject into an EnvironmentFile are refused before staging."""

    def test_every_runtime_environment_secret_is_guarded_before_rendering(self) -> None:
        cases = (
            (
                "NAS/authentik-bootstrap-password",
                "pw\nAUTHENTIK_INJECTED=1xxxxxxxxxxxxxxx",
                "Authentik bootstrap password",
            ),
            ("NAS/vaultwarden-oidc-client-secret", "secret'\nADMIN_TOKEN='x", "Vaultwarden OIDC client secret"),
            ("NAS/ntfy-admin-password", "password with spaces!!", "ntfy administrator password"),
            ("NAS/ntfy-alert-topic", 'topic"\nuser = "attacker:password"', "ntfy alert topic"),
            ("NAS/authentik-api-token", "$(touch /tmp/nas-injected)-token", "Authentik API token"),
        )
        for entry, value, label in cases:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as raw:
                nas = Appliance(pathlib.Path(raw))
                nas.initialise()
                data = json.loads(nas.db.read_text(encoding="utf-8"))
                data["entries"][entry] = value.replace("\n", " ")
                nas.db.write_text(json.dumps(data), encoding="utf-8")
                result = nas.run("activate-stdin")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"{label} has an unsafe or unexpected format in KeePassXC.", result.stderr)
                self.assertFalse(nas.path(SECRET_ROOT).exists())
                self.assertFalse(re.search(r"\bstop\b", json.dumps(nas.calls("systemctl"))))


class KeePassPasswordInputTests(unittest.TestCase):
    def test_stdin_password_is_one_bounded_line(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            nas = Appliance(pathlib.Path(raw))
            data = json.loads(nas.db.read_text(encoding="utf-8"))
            data["password"] = "p" * 4096
            nas.db.write_text(json.dumps(data), encoding="utf-8")
            accepted = nas.run("show-zfs-key-stdin", stdin="p" * 4096 + "\n")
            self.assertNotIn("exceeds 4096", accepted.stderr)
            self.assertIn("Unable to retrieve KeePassXC entry", accepted.stderr, "the 4096-character password unlocked")
            rejected = nas.run("show-zfs-key-stdin", stdin="p" * 5000 + "\n")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("exceeds 4096", rejected.stderr)
            self.assertNotIn(PASSWORD, accepted.stderr + rejected.stderr)


if __name__ == "__main__":
    unittest.main()
