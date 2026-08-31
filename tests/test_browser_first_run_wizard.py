"""Contracts for the GUI first-start browser driver used by the VM fixtures."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr
from io import StringIO
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_wizard():
    selenium = types.ModuleType("selenium")
    webdriver = types.ModuleType("selenium.webdriver")
    common = types.ModuleType("selenium.common")
    exceptions = types.ModuleType("selenium.common.exceptions")
    webdriver_common = types.ModuleType("selenium.webdriver.common")
    by = types.ModuleType("selenium.webdriver.common.by")
    support = types.ModuleType("selenium.webdriver.support")
    support_ui = types.ModuleType("selenium.webdriver.support.ui")

    class DummyChrome:
        pass

    class DummyChromeOptions:
        def set_capability(self, *_args, **_kwargs):
            pass

        def add_argument(self, *_args, **_kwargs):
            pass

    class DummyBy:
        CSS_SELECTOR = "css selector"
        TAG_NAME = "tag name"

    class DummyWait:
        pass

    class DummySeleniumError(Exception):
        pass

    setattr(webdriver, "Chrome", DummyChrome)
    setattr(webdriver, "ChromeOptions", DummyChromeOptions)
    setattr(by, "By", DummyBy)
    setattr(support_ui, "WebDriverWait", DummyWait)
    setattr(exceptions, "TimeoutException", DummySeleniumError)
    setattr(exceptions, "WebDriverException", DummySeleniumError)
    setattr(selenium, "webdriver", webdriver)
    setattr(common, "exceptions", exceptions)
    setattr(webdriver_common, "by", by)
    setattr(support, "ui", support_ui)

    replacements = {
        "selenium": selenium,
        "selenium.webdriver": webdriver,
        "selenium.common": common,
        "selenium.common.exceptions": exceptions,
        "selenium.webdriver.common": webdriver_common,
        "selenium.webdriver.common.by": by,
        "selenium.webdriver.support": support,
        "selenium.webdriver.support.ui": support_ui,
    }
    with mock.patch.dict(sys.modules, replacements):
        spec = importlib.util.spec_from_file_location(
            "first_run_wizard_under_test",
            ROOT / "tests" / "browser" / "first-run-wizard.py",
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


class WizardSecretInputTests(unittest.TestCase):
    def test_password_files_are_read_without_symlinks_or_permissive_modes(self) -> None:
        wizard = load_wizard()
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            secret = root / "secret"
            secret.write_text("value\n", encoding="utf-8")
            secret.chmod(0o600)
            self.assertEqual(wizard.read_secret(str(secret)), "value")

            link = root / "link"
            link.symlink_to(secret)
            if hasattr(os, "O_NOFOLLOW"):
                with self.assertRaises((ValueError, OSError)):
                    wizard.read_secret(str(link))

            loose = root / "loose"
            loose.write_text("value\n", encoding="utf-8")
            loose.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "group/world accessible"):
                wizard.read_secret(str(loose))

            multiline = root / "multiline"
            multiline.write_text("one\ntwo\n", encoding="utf-8")
            multiline.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "Invalid one-line"):
                wizard.read_secret(str(multiline))

            directory = root / "dir"
            directory.mkdir()
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                wizard.read_secret(str(directory))

            empty = root / "empty"
            empty.write_text("\n", encoding="utf-8")
            empty.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "Invalid one-line"):
                wizard.read_secret(str(empty))


class WizardFlowContractTests(unittest.TestCase):
    def test_login_waits_for_authentik_to_leave_the_authentication_flow(self) -> None:
        wizard = load_wizard()
        origin = "https://nas-test.local:8443"
        self.assertFalse(
            wizard.login_complete_url(
                origin + "/identity/if/flow/default-authentication-flow/",
                origin,
            )
        )
        self.assertFalse(wizard.login_complete_url("https://attacker.invalid/setup/", origin))
        self.assertTrue(wizard.login_complete_url(origin + "/identity/if/user/", origin))
        self.assertTrue(wizard.login_complete_url(origin + "/setup/", origin))

    def test_driver_targets_the_standalone_first_start_page_and_documented_fields(self) -> None:
        source = (ROOT / "tests" / "browser" / "first-run-wizard.py").read_text(encoding="utf-8")
        self.assertIn('origin.rstrip("/") + "/setup/"', source)
        for field in (
            "#wizard-keepass-password",
            "#wizard-admin-username",
            "#wizard-admin-name",
            "#wizard-admin-email",
            "#wizard-admin-password",
            "#wizard-destructive",
        ):
            self.assertIn(field, source)
        self.assertIn("#wizard-plan-devices", source)
        self.assertIn('"Run setup"', source)
        self.assertIn("akadmin", source)

    def test_wizard_reads_every_password_file_before_touching_the_browser(self) -> None:
        source = (ROOT / "tests" / "browser" / "first-run-wizard.py").read_text(encoding="utf-8")
        bootstrap = source.index("read_secret(args.bootstrap_password_file)")
        kee_pass = source.index("read_secret(args.keepass_password_file)")
        admin = source.index("read_secret(args.admin_password_file)")
        browser_call = source.index("driver = browser()")
        self.assertLess(max(bootstrap, kee_pass, admin), browser_call)

    def test_job_polling_treats_terminal_states_and_dumps_diagnostics(self) -> None:
        source = (ROOT / "tests" / "browser" / "first-run-wizard.py").read_text(encoding="utf-8")
        self.assertIn('{"complete", "complete-unverified", "failed"}', source)
        self.assertIn("browser_diagnostics(driver)", source)
        self.assertIn("--result-file", source)

    def test_diagnostic_capture_omits_input_values(self) -> None:
        wizard = load_wizard()
        driver = mock.MagicMock()
        driver.current_url = "https://nas-test.local:8443/console/"
        driver.title = "Cockpit"
        body = mock.MagicMock()
        body.text = "First start\nStart"
        pre = mock.MagicMock()
        pre.text = '{"jobId": "abc", "status": "running"}'
        driver.find_element.side_effect = lambda by, selector: pre if selector == "pre.nas-pre" else body
        driver.get_log.return_value = []

        buffer = StringIO()
        with redirect_stderr(buffer):
            diagnostics = wizard.browser_diagnostics(driver)
        self.assertNotIn("nas-pre", json.dumps(diagnostics))
        self.assertIn("First start", diagnostics["body"])
        self.assertNotIn("value=", diagnostics["body"])
        self.assertNotIn("password", json.dumps(diagnostics["console"]))


class WizardMainFailureTests(unittest.TestCase):
    def test_missing_secret_fails_before_launching_a_browser(self) -> None:
        wizard = load_wizard()
        with tempfile.TemporaryDirectory() as raw:
            missing = pathlib.Path(raw) / "missing"
            argv = [
                "first-run-wizard.py",
                "--origin",
                "https://nas-test.local:8443",
                "--bootstrap-password-file",
                str(missing),
                "--keepass-password-file",
                str(missing),
                "--admin-username",
                "nasadmin",
                "--admin-name",
                "NAS Administrator",
                "--admin-email",
                "nasadmin@nas-test.local",
                "--admin-password-file",
                str(missing),
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(wizard, "browser", side_effect=AssertionError("browser must not launch")),
                self.assertRaises((ValueError, OSError)),
                redirect_stderr(StringIO()),
            ):
                wizard.main()


if __name__ == "__main__":
    unittest.main()
