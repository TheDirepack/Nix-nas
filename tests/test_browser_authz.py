from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr
from io import StringIO
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_authz():
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
        def __init__(self, *_args, **_kwargs):
            pass

    class DummySeleniumError(Exception):
        pass

    setattr(webdriver, "Chrome", DummyChrome)
    setattr(webdriver, "ChromeOptions", DummyChromeOptions)
    setattr(exceptions, "NoSuchElementException", DummySeleniumError)
    setattr(exceptions, "TimeoutException", DummySeleniumError)
    setattr(exceptions, "WebDriverException", DummySeleniumError)
    setattr(by, "By", DummyBy)
    setattr(support_ui, "WebDriverWait", DummyWait)
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
            "nas_browser_authz_tested", ROOT / "tests" / "browser" / "authz.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


class BrowserAuthzInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authz = load_authz()

    @staticmethod
    def secret(root: pathlib.Path, name: str, value: str) -> pathlib.Path:
        path = root / name
        path.write_text(value + "\n", encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_cli_reads_all_password_files_before_first_browser_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            operator = self.secret(root, "operator", "operator-secret")
            alice = self.secret(root, "alice", "alice-secret")
            baseline = self.secret(root, "baseline", "baseline-secret")
            sentinel = RuntimeError("first-browser-operation")
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "authz.py",
                        "--cockpit-password-file",
                        str(operator),
                        "--operator-password-file",
                        str(operator),
                        "--alice-password-file",
                        str(alice),
                        "--baseline-password-file",
                        str(baseline),
                    ],
                ),
                mock.patch.object(
                    self.authz,
                    "verify_cockpit_react_interactions",
                    side_effect=sentinel,
                ) as first_browser,
            ):
                with self.assertRaisesRegex(RuntimeError, "first-browser-operation"):
                    self.authz.main()
            first_browser.assert_called_once_with("https://nas-test.local", "admin", "operator-secret")

    def test_bootstrap_only_cli_checks_akadmin_portal_setup_and_console_routes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            password = self.secret(pathlib.Path(temporary), "bootstrap", "bootstrap-secret")
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "authz.py",
                        "--origin",
                        "https://nas-test.local:8443",
                        "--bootstrap-only",
                        "--bootstrap-password-file",
                        str(password),
                    ],
                ),
                mock.patch.object(self.authz, "run_account") as run_account,
                mock.patch.object(self.authz, "verify_callback_return_paths") as callback_paths,
                mock.patch.object(self.authz, "verify_launcher_opens_console") as launcher_console,
            ):
                self.assertEqual(self.authz.main(), 0)

        origin, username, secret, expectations, settings = run_account.call_args.args
        self.assertEqual(
            (origin, username, secret, settings), ("https://nas-test.local:8443", "akadmin", "bootstrap-secret", False)
        )
        self.assertEqual(
            [(item.path, item.allowed) for item in expectations], [("/", True), ("/setup", True), ("/console/", True)]
        )
        callback_paths.assert_called_once_with(
            "https://nas-test.local:8443", "akadmin", "bootstrap-secret", ["/setup", "/console/"]
        )
        launcher_console.assert_called_once_with("https://nas-test.local:8443", "akadmin", "bootstrap-secret")

    def test_callback_return_accepts_caddys_canonical_trailing_slash(self) -> None:
        self.assertTrue(self.authz.callback_return_matches("/setup", "/setup/"))
        self.assertTrue(self.authz.callback_return_matches("/console/", "/console/"))
        self.assertFalse(self.authz.callback_return_matches("/setup", "/console/"))

    def test_callback_return_accepts_cockpits_default_console_landing(self) -> None:
        self.assertTrue(self.authz.callback_return_matches("/console/", "/console/system"))
        self.assertFalse(self.authz.callback_return_matches("/setup", "/console/system"))
        self.assertFalse(self.authz.callback_return_matches("/console/", "/identity/if/user/"))

    def test_secret_reader_rejects_symlink_and_permissive_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            secure = self.secret(root, "secure", "secret")
            link = root / "link"
            link.symlink_to(secure)
            with self.assertRaises((OSError, ValueError)):
                self.authz.read_secret(str(link))
            secure.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "group/world accessible"):
                self.authz.read_secret(str(secure))

    def test_native_share_route_checks_response_without_executing_error_page(self) -> None:
        with mock.patch.object(
            self.authz,
            "native_share_response",
            return_value={"status": 403, "url": "https://nas-test.local/share/not-a-real-token"},
        ) as fetch:
            self.authz.verify_native_share_route(object(), "https://nas-test.local")
        fetch.assert_called_once_with("https://nas-test.local")

    def test_native_share_route_rejects_authentik_redirect(self) -> None:
        with mock.patch.object(
            self.authz,
            "native_share_response",
            return_value={"status": 302, "url": "https://nas-test.local/identity/if/flow/login/"},
        ):
            with self.assertRaisesRegex(RuntimeError, "intercepted by Authentik"):
                self.authz.verify_native_share_route(object(), "https://nas-test.local")

    def test_hostile_identity_text_check_includes_open_shadow_roots(self) -> None:
        driver = mock.Mock()
        driver.execute_script.return_value = {
            "injectedImage": False,
            "executionMarker": None,
        }
        with mock.patch.object(
            self.authz,
            "rendered_text",
            return_value="Account <img src=x onerror=document.body.dataset.nasXss=1>",
        ):
            self.authz.verify_no_identity_markup_injection(driver, "alice")

    def test_browser_stage_reports_the_failed_stage_and_diagnostics(self) -> None:
        output = StringIO()

        def fail_browser() -> None:
            raise RuntimeError("browser failure")

        with (
            mock.patch.object(
                self.authz,
                "browser_diagnostics",
                return_value={"url": "https://nas-test.local/", "body": "failure page"},
            ),
            redirect_stderr(output),
        ):
            with self.assertRaisesRegex(RuntimeError, "browser failure"):
                self.authz.browser_step(mock.Mock(), "Portal capability routes (alice)", fail_browser)
        self.assertIn("VM-BROWSER-STAGE-START: Portal capability routes (alice)", output.getvalue())
        self.assertIn("VM-BROWSER-STAGE-FAIL: Portal capability routes (alice)", output.getvalue())
        self.assertIn("VM-BROWSER-DIAGNOSTICS:", output.getvalue())

    def test_browser_diagnostics_redact_url_query_and_fragment(self) -> None:
        self.assertEqual(
            self.authz.safe_browser_url("https://nas.example/console/?token=secret#auth-code"),
            "https://nas.example/console/",
        )

    def test_login_discards_pre_authentication_browser_diagnostics(self) -> None:
        driver = mock.Mock()
        self.authz.discard_browser_log(driver)
        driver.get_log.assert_called_once_with("browser")

    def test_discard_browser_log_ignores_unavailable_log(self) -> None:
        driver = mock.Mock()
        driver.get_log.side_effect = ValueError("log unavailable")
        self.authz.discard_browser_log(driver)

    def test_allowed_settings_route_accepts_its_authentik_flow_redirect(self) -> None:
        expectation = self.authz.RouteExpectation("/settings/syncthing", True, "/identity/if/flow/nas-user-settings/")
        with mock.patch.object(
            self.authz,
            "fetch_status",
            return_value={
                "status": 200,
                "url": "https://nas-test.local/identity/if/flow/nas-user-settings/",
            },
        ):
            self.authz.verify_routes(object(), [expectation])

    def test_allowed_route_rejects_unexpected_authentik_redirect(self) -> None:
        with mock.patch.object(
            self.authz,
            "fetch_status",
            return_value={"status": 200, "url": "https://nas-test.local/identity/if/flow/login/"},
        ):
            with self.assertRaisesRegex(RuntimeError, "expectedAllowed"):
                self.authz.verify_routes(object(), [self.authz.RouteExpectation("/shares/", True)])

    def test_allowed_route_retries_copy_party_first_user_reload(self) -> None:
        with (
            mock.patch.object(
                self.authz,
                "fetch_status",
                side_effect=[
                    {"status": 403, "url": "https://nas-test.local/shares/"},
                    {"status": 200, "url": "https://nas-test.local/shares/"},
                ],
            ) as fetch,
            mock.patch.object(self.authz.time, "sleep"),
        ):
            self.authz.verify_routes(object(), [self.authz.RouteExpectation("/shares/", True)])
        self.assertEqual(fetch.call_count, 2)

    def test_allowed_route_waits_for_slow_copy_party_first_user_reload(self) -> None:
        responses = [{"status": 403, "url": "https://nas-test.local/shares/"}] * 29
        responses.append({"status": 200, "url": "https://nas-test.local/shares/"})
        with (
            mock.patch.object(self.authz, "fetch_status", side_effect=responses) as fetch,
            mock.patch.object(self.authz.time, "sleep"),
        ):
            self.authz.verify_routes(object(), [self.authz.RouteExpectation("/shares/", True)])
        self.assertEqual(fetch.call_count, self.authz.ALLOWED_ROUTE_RETRY_ATTEMPTS)

    def test_allowed_route_rejects_service_unavailable(self) -> None:
        with (
            mock.patch.object(
                self.authz,
                "fetch_status",
                return_value={"status": 503, "url": "https://nas-test.local/ai/"},
            ),
            mock.patch.object(self.authz.time, "sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, '"status": 503'):
                self.authz.verify_routes(object(), [self.authz.RouteExpectation("/ai/", True)])


if __name__ == "__main__":
    unittest.main()
