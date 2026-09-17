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
    chrome = types.ModuleType("selenium.webdriver.chrome")
    chrome_service = types.ModuleType("selenium.webdriver.chrome.service")
    support = types.ModuleType("selenium.webdriver.support")
    support_ui = types.ModuleType("selenium.webdriver.support.ui")

    class DummyChrome:
        pass

    class DummyChromeOptions:
        def __init__(self):
            self.arguments: list[str] = []

        def set_capability(self, *_args, **_kwargs):
            pass

        def add_argument(self, argument, *_args, **_kwargs):
            self.arguments.append(argument)

    class DummyService:
        def __init__(self, **_kwargs):
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
    setattr(chrome_service, "Service", DummyService)
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
        "selenium.webdriver.chrome": chrome,
        "selenium.webdriver.chrome.service": chrome_service,
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
            administrator = self.secret(root, "administrator", "administrator-secret")
            operator = self.secret(root, "operator", "operator-secret")
            alice = self.secret(root, "alice", "alice-secret")
            baseline = self.secret(root, "baseline", "baseline-secret")
            post_a = self.secret(root, "post-a", "post-a-secret")
            post_b = self.secret(root, "post-b", "post-b-secret")
            sentinel = RuntimeError("first-browser-operation")
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "authz.py",
                        "--administrator-password-file",
                        str(administrator),
                        "--operator-password-file",
                        str(operator),
                        "--alice-password-file",
                        str(alice),
                        "--baseline-password-file",
                        str(baseline),
                        "--post-a-password-file",
                        str(post_a),
                        "--post-b-password-file",
                        str(post_b),
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
            first_browser.assert_called_once_with("https://nas-test.local", "nasadmin", "administrator-secret")

    def test_browser_pins_the_vm_public_hostname_to_loopback(self) -> None:
        options = self.authz.webdriver.ChromeOptions()
        chrome_service = types.ModuleType("selenium.webdriver.chrome.service")

        class DummyService:
            def __init__(self, **_kwargs):
                pass

        setattr(chrome_service, "Service", DummyService)
        with (
            mock.patch.object(self.authz.webdriver, "ChromeOptions", return_value=options),
            mock.patch.object(self.authz.shutil, "which", side_effect=["/bin/chromium", "/bin/chromedriver"]),
            mock.patch.object(self.authz.webdriver, "Chrome"),
            mock.patch.dict(sys.modules, {"selenium.webdriver.chrome.service": chrome_service}),
            mock.patch.dict(self.authz.os.environ, {"NAS_BROWSER_HOST_ADDRESS": "10.0.2.15"}),
        ):
            self.authz.browser()
        self.assertIn("--host-resolver-rules=MAP nas-test.local 10.0.2.15", options.arguments)

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

    def test_syncthing_admin_only_cli_checks_global_folder_visibility(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            password = self.secret(pathlib.Path(temporary), "administrator", "administrator-secret")
            driver = mock.MagicMock()
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "authz.py",
                        "--syncthing-admin-only",
                        "--administrator-password-file",
                        str(password),
                    ],
                ),
                mock.patch.object(self.authz, "browser", return_value=driver),
                mock.patch.object(self.authz, "login") as login,
                mock.patch.object(self.authz, "verify_routes") as routes,
                mock.patch.object(self.authz, "verify_administrator_syncthing_folders") as folders,
            ):
                self.assertEqual(self.authz.main(), 0)

        login.assert_called_once_with(driver, "https://nas-test.local", "nasadmin", "administrator-secret")
        routes.assert_called_once()
        folders.assert_called_once_with(driver, ["post-a", "post-b"])
        driver.quit.assert_called_once_with()

    def test_identity_xss_only_cli_requires_and_verifies_hostile_display_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            password = self.secret(pathlib.Path(temporary), "alice", "alice-secret")
            driver = mock.MagicMock()
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["authz.py", "--identity-xss-only", "--alice-password-file", str(password)],
                ),
                mock.patch.object(self.authz, "browser", return_value=driver),
                mock.patch.object(self.authz, "login") as login,
                mock.patch.object(self.authz, "verify_no_identity_markup_injection") as injection,
            ):
                self.assertEqual(self.authz.main(), 0)

        login.assert_called_once_with(driver, "https://nas-test.local", "alice", "alice-secret")
        injection.assert_called_once_with(driver, "alice", require_hostile_display_name=True)
        driver.quit.assert_called_once_with()

    def test_callback_return_accepts_caddys_canonical_trailing_slash(self) -> None:
        self.assertTrue(self.authz.callback_return_matches("/setup", "/setup/"))
        self.assertTrue(self.authz.callback_return_matches("/console/", "/console/"))
        self.assertFalse(self.authz.callback_return_matches("/setup", "/console/"))

    def test_callback_return_accepts_cockpits_default_console_landing(self) -> None:
        self.assertTrue(self.authz.callback_return_matches("/console/", "/console/system"))
        self.assertFalse(self.authz.callback_return_matches("/setup", "/console/system"))
        self.assertFalse(self.authz.callback_return_matches("/console/", "/identity/if/user/"))

    def test_launcher_accepts_cockpits_default_console_landing(self) -> None:
        driver = mock.Mock()
        driver.current_url = "https://nas-test.local/console/system"
        launcher_link = driver.find_element.return_value
        launcher_link.is_displayed.return_value = True
        driver.find_elements.return_value = []
        wait = mock.Mock()

        def wait_until(predicate):
            result = predicate(driver)
            if not result:
                raise self.authz.TimeoutException()
            return result

        wait.until.side_effect = wait_until
        with (
            mock.patch.object(self.authz, "browser", return_value=driver),
            mock.patch.object(self.authz, "login"),
            mock.patch.object(self.authz, "WebDriverWait", return_value=wait),
        ):
            self.authz.verify_launcher_opens_console("https://nas-test.local", "akadmin", "secret")

        launcher_link.click.assert_called_once_with()
        driver.quit.assert_called_once_with()

    def test_cockpit_login_retries_transient_denial_with_top_level_navigation(self) -> None:
        driver = mock.Mock()
        driver.current_url = "https://nas-test.local/console/"
        driver.find_elements.return_value = []
        pages = iter(["Access was denied HTTP ERROR 403 Reload", "Cockpit"])

        def navigate(_url: str) -> None:
            driver.page_source = next(pages)

        driver.get.side_effect = navigate
        wait = mock.Mock()
        wait.until.side_effect = lambda predicate: predicate(driver)
        with (
            mock.patch.object(self.authz, "login") as login,
            mock.patch.object(self.authz, "WebDriverWait", return_value=wait),
            mock.patch.object(self.authz.time, "sleep") as sleep,
        ):
            self.authz.cockpit_login(driver, "https://nas-test.local", "nasadmin", "secret")

        login.assert_called_once_with(driver, "https://nas-test.local", "nasadmin", "secret")
        self.assertEqual(driver.get.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_cockpit_destination_rejects_chrome_http_error_page(self) -> None:
        driver = mock.Mock()
        driver.current_url = "https://nas-test.local/console/"
        driver.page_source = "Access was denied HTTP ERROR 403 Reload"
        driver.find_elements.return_value = []
        self.assertFalse(self.authz.cockpit_destination_loaded(driver, "https://nas-test.local"))

    def test_cockpit_login_restarts_one_persistently_denied_session(self) -> None:
        driver = mock.Mock()
        driver.current_url = "https://nas-test.local/console/"
        driver.find_elements.return_value = []
        pages = iter(["HTTP ERROR 403", "HTTP ERROR 403", "Cockpit"])
        driver.get.side_effect = lambda _url: setattr(driver, "page_source", next(pages))
        wait = mock.Mock()
        wait.until.side_effect = lambda predicate: predicate(driver)
        with (
            mock.patch.object(self.authz, "login") as login,
            mock.patch.object(self.authz, "WebDriverWait", return_value=wait),
            mock.patch.object(self.authz, "COCKPIT_ROUTE_RETRY_ATTEMPTS", 2),
            mock.patch.object(self.authz, "reset_browser_session") as reset_session,
            mock.patch.object(self.authz.time, "sleep"),
        ):
            self.authz.cockpit_login(driver, "https://nas-test.local", "nasadmin", "secret")

        self.assertEqual(login.call_count, 2)
        reset_session.assert_called_once_with(driver, "https://nas-test.local")
        self.assertEqual(driver.get.call_count, 3)

    def test_cockpit_login_fails_closed_after_persistent_denial(self) -> None:
        driver = mock.Mock()
        driver.current_url = "https://nas-test.local/console/"
        driver.page_source = "Access was denied HTTP ERROR 403 Reload"
        driver.find_elements.return_value = []
        wait = mock.Mock()
        wait.until.side_effect = lambda predicate: predicate(driver)
        with (
            mock.patch.object(self.authz, "login") as login,
            mock.patch.object(self.authz, "WebDriverWait", return_value=wait),
            mock.patch.object(self.authz, "COCKPIT_ROUTE_RETRY_ATTEMPTS", 2),
            mock.patch.object(self.authz, "reset_browser_session") as reset_session,
            mock.patch.object(self.authz.time, "sleep"),
            mock.patch.object(self.authz, "browser_diagnostics", return_value={"body": "HTTP ERROR 403"}),
        ):
            with self.assertRaisesRegex(RuntimeError, "Cockpit route did not become ready"):
                self.authz.cockpit_login(driver, "https://nas-test.local", "nasadmin", "secret")
        self.assertEqual(login.call_count, 2)
        reset_session.assert_called_once_with(driver, "https://nas-test.local")
        self.assertEqual(driver.get.call_count, 4)

    def test_cockpit_login_does_not_restart_session_for_502(self) -> None:
        driver = mock.Mock()
        driver.current_url = "https://nas-test.local/console/"
        driver.page_source = "HTTP ERROR 502"
        driver.find_elements.return_value = []
        wait = mock.Mock()
        wait.until.side_effect = lambda predicate: predicate(driver)
        with (
            mock.patch.object(self.authz, "login") as login,
            mock.patch.object(self.authz, "WebDriverWait", return_value=wait),
            mock.patch.object(self.authz, "COCKPIT_ROUTE_RETRY_ATTEMPTS", 2),
            mock.patch.object(self.authz, "reset_browser_session") as reset_session,
            mock.patch.object(self.authz.time, "sleep"),
            mock.patch.object(self.authz, "browser_diagnostics", return_value={"body": "HTTP ERROR 502"}),
        ):
            with self.assertRaisesRegex(RuntimeError, "Cockpit route did not become ready"):
                self.authz.cockpit_login(driver, "https://nas-test.local", "nasadmin", "secret")

        login.assert_called_once_with(driver, "https://nas-test.local", "nasadmin", "secret")
        reset_session.assert_not_called()

    def test_reset_browser_session_clears_cookies_and_origin_storage(self) -> None:
        driver = mock.Mock()
        self.authz.reset_browser_session(driver, "https://nas-test.local/")

        driver.get.assert_called_once_with("about:blank")
        self.assertEqual(
            driver.execute_cdp_cmd.call_args_list,
            [
                mock.call("Network.clearBrowserCookies", {}),
                mock.call(
                    "Storage.clearDataForOrigin",
                    {"origin": "https://nas-test.local", "storageTypes": "all"},
                ),
            ],
        )

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

    def test_native_share_probe_uses_loopback_for_vm_host_mapping(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 404
        response.geturl.return_value = "https://nas-test.local:8443/share/not-a-real-token"
        opener = mock.Mock()
        opener.open.return_value = response
        with (
            mock.patch.object(self.authz.urllib.request, "build_opener", return_value=opener) as build_opener,
            mock.patch.dict(self.authz.os.environ, {"NAS_BROWSER_HOST_ADDRESS": "10.0.2.15"}),
        ):
            result = self.authz.native_share_response("https://nas-test.local:8443")
        request = opener.open.call_args.args[0]
        self.assertEqual(result["status"], 404)
        self.assertEqual(request.full_url, "https://nas-test.local:8443/share/not-a-real-token")
        self.assertEqual(request.get_header("Host"), "nas-test.local:8443")
        build_opener.assert_called_once()

    def test_native_share_route_rejects_authentik_redirect(self) -> None:
        with mock.patch.object(
            self.authz,
            "native_share_response",
            return_value={"status": 302, "url": "https://nas-test.local/identity/if/flow/login/"},
        ):
            with self.assertRaisesRegex(RuntimeError, "intercepted by Authentik"):
                self.authz.verify_native_share_route(object(), "https://nas-test.local")

    def test_hostile_identity_check_reads_exact_name_from_current_user_api(self) -> None:
        driver = mock.Mock()
        driver.execute_script.return_value = {
            "injectedImage": False,
            "executionMarker": None,
        }
        identity = {
            "status": 200,
            "body": '{"user":{"name":"<img src=x onerror=document.body.dataset.nasXss=1>"}}',
        }
        with mock.patch.object(
            self.authz,
            "fetch_request",
            return_value=identity,
        ) as request:
            self.authz.verify_no_identity_markup_injection(driver, "alice", require_hostile_display_name=True)
        request.assert_called_once_with(driver, "/identity/api/v3/core/users/me/", "GET")

    def test_hostile_identity_check_rejects_wrong_current_user_name(self) -> None:
        driver = mock.Mock()
        driver.execute_script.return_value = {
            "injectedImage": False,
            "executionMarker": None,
        }
        with mock.patch.object(
            self.authz,
            "fetch_request",
            return_value={"status": 200, "body": '{"user":{"name":"Alice Example"}}'},
        ):
            with self.assertRaisesRegex(RuntimeError, "did not contain the hostile display name"):
                self.authz.verify_no_identity_markup_injection(driver, "alice", require_hostile_display_name=True)

    def test_hostile_identity_check_rejects_dom_injection_signals(self) -> None:
        for result in (
            {"injectedImage": True, "executionMarker": None},
            {"injectedImage": False, "executionMarker": "1"},
        ):
            with self.subTest(result=result):
                driver = mock.Mock()
                driver.execute_script.return_value = result
                with self.assertRaisesRegex(RuntimeError, "executed identity-derived HTML"):
                    self.authz.verify_no_identity_markup_injection(driver, "alice")

    def test_hostile_identity_check_scans_open_shadow_roots_and_same_origin_frames(self) -> None:
        driver = mock.Mock()
        driver.execute_script.return_value = {
            "injectedImage": False,
            "executionMarker": None,
        }
        self.authz.verify_no_identity_markup_injection(driver, "alice")
        script = driver.execute_script.call_args.args[0]
        self.assertIn("element.shadowRoot", script)
        self.assertIn("element.contentDocument", script)

    def test_rendering_quality_ignores_overflow_from_hidden_content(self) -> None:
        driver = mock.Mock()
        driver.execute_script.return_value = {
            "viewport": 305,
            "documentWidth": 325,
            "bodyWidth": 325,
            "overflow": [],
            "visibleOverflow": [],
            "duplicates": [],
        }
        driver.get_log.return_value = []
        with mock.patch.object(self.authz, "WebDriverWait"):
            self.authz.verify_rendering_quality(driver, "Authentik portal")

    def test_rendering_quality_rejects_visible_document_overflow(self) -> None:
        driver = mock.Mock()
        driver.execute_script.return_value = {
            "viewport": 305,
            "documentWidth": 325,
            "bodyWidth": 325,
            "overflow": [],
            "visibleOverflow": [{"tag": "DIV", "left": 300, "right": 325}],
            "duplicates": [],
        }
        driver.get_log.return_value = []
        with mock.patch.object(self.authz, "WebDriverWait"):
            with self.assertRaisesRegex(RuntimeError, "horizontal-overflow"):
                self.authz.verify_rendering_quality(driver, "Authentik portal")

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

    def test_cockpit_discards_shell_logs_after_the_nas_page_loads(self) -> None:
        driver = mock.Mock()
        events = []

        def run_stage(_driver, label, operation):
            if label in {"Cockpit NAS page", "Cockpit rendering and console"}:
                operation()

        with (
            mock.patch.object(self.authz, "browser", return_value=driver),
            mock.patch.object(self.authz, "browser_step", side_effect=run_stage),
            mock.patch.object(self.authz, "WebDriverWait"),
            mock.patch.object(self.authz, "wait_for_page_text"),
            mock.patch.object(self.authz, "discard_browser_log", side_effect=lambda _driver: events.append("discard")),
            mock.patch.object(
                self.authz,
                "verify_rendering_quality",
                side_effect=lambda _driver, _label: events.append("render"),
            ),
        ):
            self.authz.verify_cockpit_react_interactions("https://nas-test.local", "nasadmin", "secret")

        self.assertEqual(events, ["discard", "render"])

    def test_login_retries_transient_authentik_flow_502(self) -> None:
        driver = mock.Mock()
        diagnostics = {
            "url": "https://nas-test.local/identity/if/flow/default-authentication-flow/",
            "body": "Response returned an error code\nPowered by authentik",
            "console": [
                {
                    "message": "502 POST /identity/api/v3/flows/executor/default-authentication-flow/",
                }
            ],
        }
        with (
            mock.patch.object(
                self.authz,
                "_login_once",
                side_effect=[self.authz.TimeoutException(), None],
            ) as login_once,
            mock.patch.object(self.authz, "browser_diagnostics", return_value=diagnostics),
            mock.patch.object(self.authz, "reset_browser_session") as reset_session,
            mock.patch.object(self.authz.time, "sleep") as sleep,
        ):
            self.authz.login(driver, "https://nas-test.local", "post-b", "secret")

        self.assertEqual(login_once.call_count, 2)
        reset_session.assert_called_once_with(driver, "https://nas-test.local")
        sleep.assert_called_once_with(1)

    def test_login_fails_closed_after_persistent_authentik_flow_502(self) -> None:
        driver = mock.Mock()
        diagnostics = {
            "url": "https://nas-test.local/identity/if/flow/default-authentication-flow/",
            "body": "Response returned an error code",
            "console": [
                {
                    "message": (
                        "Failed to load resource: the server responded with a status of 502 "
                        "/identity/api/v3/flows/executor/default-authentication-flow/"
                    ),
                }
            ],
        }
        with (
            mock.patch.object(self.authz, "_login_once", side_effect=self.authz.TimeoutException()) as login_once,
            mock.patch.object(self.authz, "browser_diagnostics", return_value=diagnostics),
            mock.patch.object(self.authz, "reset_browser_session") as reset_session,
            mock.patch.object(self.authz.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(RuntimeError, "Authentik browser login did not complete"):
                self.authz.login(driver, "https://nas-test.local", "post-b", "secret")

        self.assertEqual(login_once.call_count, 2)
        reset_session.assert_called_once_with(driver, "https://nas-test.local")
        sleep.assert_called_once_with(1)

    def test_login_does_not_retry_unrelated_502(self) -> None:
        driver = mock.Mock()
        diagnostics = {
            "url": "https://nas-test.local/identity/if/flow/default-authentication-flow/",
            "body": "Response returned an error code",
            "console": [{"message": "502 GET /identity/static/app.js"}],
        }
        with (
            mock.patch.object(self.authz, "_login_once", side_effect=self.authz.TimeoutException()) as login_once,
            mock.patch.object(self.authz, "browser_diagnostics", return_value=diagnostics),
            mock.patch.object(self.authz, "reset_browser_session") as reset_session,
            mock.patch.object(self.authz.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(RuntimeError, "Authentik browser login did not complete"):
                self.authz.login(driver, "https://nas-test.local", "post-b", "secret")

        login_once.assert_called_once()
        reset_session.assert_not_called()
        sleep.assert_not_called()

    def test_portal_readiness_waits_for_applications_instead_of_loading_shell(self) -> None:
        driver = mock.Mock()
        driver.current_url = "https://nas-test.local/identity/if/user/"
        driver.execute_script.return_value = "complete"
        with mock.patch.object(self.authz, "rendered_text", return_value="Loading"):
            self.assertFalse(self.authz.authenticated_destination_loaded(driver, "https://nas-test.local"))
        with mock.patch.object(self.authz, "rendered_text", return_value="My applications\n0 applications available"):
            self.assertTrue(self.authz.authenticated_destination_loaded(driver, "https://nas-test.local"))

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

    def test_allowed_route_rejects_launcher_fallback(self) -> None:
        with mock.patch.object(
            self.authz,
            "fetch_status",
            return_value={"status": 200, "url": "https://nas-test.local/identity/if/user/"},
        ):
            with self.assertRaisesRegex(RuntimeError, "expectedAllowed"):
                self.authz.verify_routes(object(), [self.authz.RouteExpectation("/shares/", True)])

    def test_allowed_route_denial_reports_outpost_identity_headers(self) -> None:
        driver = object()
        identity = {
            "status": 200,
            "username": "alice",
            "groups": "nas_users",
            "entitlements": "",
        }
        with (
            mock.patch.object(
                self.authz,
                "fetch_status",
                return_value={"status": 403, "url": "https://nas-test.local/shares/"},
            ),
            mock.patch.object(self.authz.time, "sleep"),
            mock.patch.object(self.authz, "fetch_outpost_identity", return_value=identity) as outpost,
        ):
            with self.assertRaisesRegex(RuntimeError, '"groups": "nas_users"'):
                self.authz.verify_routes(driver, [self.authz.RouteExpectation("/shares/", True)])
        outpost.assert_called_once_with(driver, "/shares/")

    def test_denied_route_rejects_new_authentication_flow(self) -> None:
        with mock.patch.object(
            self.authz,
            "fetch_status",
            return_value={"status": 200, "url": "https://nas-test.local/identity/if/flow/login/"},
        ):
            with self.assertRaisesRegex(RuntimeError, "expectedAllowed"):
                self.authz.verify_routes(object(), [self.authz.RouteExpectation("/console/", False)])

    def test_personal_file_operations_write_read_and_delete_inside_own_volume(self) -> None:
        responses = [
            {"status": 201, "url": "https://nas-test.local/shares/users/alice/browser-e2e.txt", "body": ""},
            {
                "status": 200,
                "url": "https://nas-test.local/shares/users/alice/browser-e2e.txt",
                "body": "browser-e2e-alice",
            },
            {"status": 204, "url": "https://nas-test.local/shares/users/alice/browser-e2e.txt", "body": ""},
        ]
        with mock.patch.object(self.authz, "fetch_request", side_effect=responses) as request:
            self.authz.verify_personal_file_operations(object(), "alice")
        self.assertEqual([call.args[2] for call in request.call_args_list], ["PUT", "GET", "DELETE"])
        self.assertTrue(all(call.args[1] == "/shares/users/alice/browser-e2e.txt" for call in request.call_args_list))

    def test_fetch_request_can_explicitly_replace_an_existing_file(self) -> None:
        driver = mock.Mock()
        driver.execute_async_script.return_value = {"status": 204, "body": ""}
        self.authz.fetch_request(driver, "/shares/users/alice/file.txt", "PUT", "new", replace=True)

        script = driver.execute_async_script.call_args.args[0]
        self.assertIn("Replace", script)
        self.assertEqual(
            driver.execute_async_script.call_args.args[1:],
            ("/shares/users/alice/file.txt", "PUT", "new", True),
        )

    def test_cross_user_personal_file_read_write_and_delete_are_all_denied(self) -> None:
        denied = {"status": 403, "url": "https://nas-test.local/shares/users/bob/isolation-e2e.txt", "body": ""}
        with mock.patch.object(self.authz, "authenticated_https_request", return_value=denied) as request:
            self.authz.verify_cross_user_file_access_blocked(object(), "https://nas-test.local", "bob")
        self.assertEqual([call.args[3] for call in request.call_args_list], ["GET", "PUT", "DELETE"])
        self.assertTrue(all(call.args[2] == "/shares/users/bob/isolation-e2e.txt" for call in request.call_args_list))

    def test_cross_user_personal_file_probe_fails_on_any_successful_operation(self) -> None:
        with mock.patch.object(
            self.authz,
            "authenticated_https_request",
            side_effect=[
                {"status": 404, "url": "https://nas-test.local/shares/users/bob/isolation-e2e.txt", "body": ""},
                {"status": 201, "url": "https://nas-test.local/shares/users/bob/isolation-e2e.txt", "body": ""},
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "cross-user PUT unexpectedly succeeded"):
                self.authz.verify_cross_user_file_access_blocked(object(), "https://nas-test.local", "bob")

    def test_authenticated_https_request_carries_browser_cookies_without_following_redirects(self) -> None:
        driver = mock.Mock()
        driver.get_cookies.return_value = [
            {"name": "authentik_session", "value": "session-value"},
            {"name": "authentik_proxy", "value": "proxy-value"},
        ]
        response = mock.Mock()
        response.status = 302
        response.read.return_value = b"redirect"
        response.getheader.return_value = "/identity/if/flow/default-authentication-flow/"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with (
            mock.patch.object(self.authz, "_PinnedHTTPSConnection", return_value=connection) as pinned,
            mock.patch.dict(self.authz.os.environ, {"NAS_BROWSER_HOST_ADDRESS": "127.0.0.1"}),
        ):
            result = self.authz.authenticated_https_request(
                driver,
                "https://nas-test.local:8443",
                "/shares/users/bob/isolation-e2e.txt",
                "PUT",
                "blocked-write",
            )

        self.assertEqual(result["status"], 302)
        pinned.assert_called_once()
        self.assertEqual(pinned.call_args.args, ("nas-test.local", "127.0.0.1"))
        self.assertEqual(pinned.call_args.kwargs["port"], 8443)
        request = connection.request.call_args
        self.assertEqual(request.args[:2], ("PUT", "/shares/users/bob/isolation-e2e.txt"))
        self.assertEqual(request.kwargs["body"], b"blocked-write")
        self.assertEqual(
            request.kwargs["headers"]["Cookie"],
            "authentik_session=session-value; authentik_proxy=proxy-value",
        )
        connection.close.assert_called_once_with()

    def test_administrator_sees_disjoint_syncthing_folders_for_each_user(self) -> None:
        folders = [
            {
                "id": "nas-post-a-backup",
                "path": "/tank/shares/users/post-a/syncthing",
                "devices": [{"deviceID": "local-device"}, {"deviceID": "device-a"}],
            },
            {
                "id": "nas-post-b-backup",
                "path": "/tank/shares/users/post-b/syncthing",
                "devices": [{"deviceID": "local-device"}, {"deviceID": "device-b"}],
            },
        ]
        driver = object()
        with mock.patch.object(
            self.authz,
            "fetch_syncthing_request",
            side_effect=[
                {
                    "status": 200,
                    "url": "https://nas-test.local/syncthing/",
                    "body": self.authz.json.dumps({"myID": "local-device"}),
                },
                {
                    "status": 200,
                    "url": "https://nas-test.local/syncthing/",
                    "body": self.authz.json.dumps(folders),
                },
            ],
        ) as request:
            self.authz.verify_administrator_syncthing_folders(driver, ["post-a", "post-b"])
        self.assertEqual(
            request.call_args_list,
            [
                mock.call(driver, "/syncthing/rest/system/status"),
                mock.call(driver, "/syncthing/rest/config/folders"),
            ],
        )

    def test_syncthing_browser_request_mirrors_ui_csrf_cookie_and_header(self) -> None:
        driver = mock.Mock()
        driver.current_url = "https://nas-test.local:8443/identity/if/user/"
        driver.get_cookies.return_value = [
            {"name": "authentik_session", "value": "session-value", "path": "/"},
            {"name": "CSRF-Token-ABC2345", "value": "csrf-value", "path": "/syncthing/"},
        ]
        driver.execute_async_script.return_value = {
            "status": 200,
            "url": "https://nas-test.local:8443/syncthing/rest/config/folders",
            "body": "[]",
        }

        result = self.authz.fetch_syncthing_request(driver, "/syncthing/rest/config/folders")

        self.assertEqual(result["status"], 200)
        driver.get.assert_called_once_with("https://nas-test.local:8443/syncthing/")
        script_call = driver.execute_async_script.call_args
        self.assertIn("headers[arguments[1]] = arguments[2]", script_call.args[0])
        self.assertEqual(
            script_call.args[1:],
            ("/syncthing/rest/config/folders", "X-CSRF-Token-ABC2345", "csrf-value"),
        )

    def test_syncthing_browser_request_requires_ui_csrf_cookie(self) -> None:
        driver = mock.Mock()
        driver.current_url = "https://nas-test.local:8443/identity/if/user/"
        driver.get_cookies.return_value = [{"name": "authentik_session", "value": "session-value", "path": "/"}]

        with self.assertRaisesRegex(RuntimeError, "Syncthing CSRF cookie is unavailable"):
            self.authz.fetch_syncthing_request(driver, "/syncthing/rest/config/folders")

        driver.execute_async_script.assert_not_called()

    def test_administrator_syncthing_probe_rejects_shared_user_device(self) -> None:
        folders = [
            {
                "id": f"nas-{username}-backup",
                "path": f"/tank/shares/users/{username}/syncthing",
                "devices": [{"deviceID": "local-device"}, {"deviceID": "shared-device"}],
            }
            for username in ("post-a", "post-b")
        ]
        with mock.patch.object(
            self.authz,
            "fetch_syncthing_request",
            side_effect=[
                {
                    "status": 200,
                    "url": "https://nas-test.local/syncthing/",
                    "body": self.authz.json.dumps({"myID": "local-device"}),
                },
                {
                    "status": 200,
                    "url": "https://nas-test.local/syncthing/",
                    "body": self.authz.json.dumps(folders),
                },
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "share a user device"):
                self.authz.verify_administrator_syncthing_folders(object(), ["post-a", "post-b"])

    def test_administrator_syncthing_probe_requires_local_device(self) -> None:
        folders = [
            {
                "id": f"nas-{username}-backup",
                "path": f"/tank/shares/users/{username}/syncthing",
                "devices": [{"deviceID": f"device-{username}"}],
            }
            for username in ("post-a", "post-b")
        ]
        with mock.patch.object(
            self.authz,
            "fetch_syncthing_request",
            side_effect=[
                {
                    "status": 200,
                    "url": "https://nas-test.local/syncthing/",
                    "body": self.authz.json.dumps({"myID": "local-device"}),
                },
                {
                    "status": 200,
                    "url": "https://nas-test.local/syncthing/",
                    "body": self.authz.json.dumps(folders),
                },
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "does not include the local device"):
                self.authz.verify_administrator_syncthing_folders(object(), ["post-a", "post-b"])

    def test_copy_party_isolation_denies_peers_and_allows_administrator(self) -> None:
        def success(status: int = 200, body: str = "") -> dict[str, object]:
            return {"status": status, "url": "https://nas-test.local/shares/", "body": body}

        browser_responses = [
            success(201),
            success(201),
            success(body="copy-party-isolation-post-a"),
            success(204),
            success(body="copy-party-isolation-post-b"),
            success(204),
            success(body="copy-party-administrator-update-post-a"),
            success(204),
            success(body="copy-party-administrator-update-post-b"),
            success(204),
        ]
        driver = mock.MagicMock()
        with (
            mock.patch.object(self.authz, "browser", return_value=driver),
            mock.patch.object(self.authz, "login") as login,
            mock.patch.object(self.authz, "verify_routes") as verify_routes,
            mock.patch.object(self.authz, "fetch_request", side_effect=browser_responses) as request,
            mock.patch.object(self.authz, "authenticated_https_request", return_value=success(403)) as peer_request,
        ):
            self.authz.verify_copy_party_user_isolation(
                "https://nas-test.local",
                ("nasadmin", "admin-secret"),
                [("post-a", "a-secret"), ("post-b", "b-secret")],
            )

        self.assertEqual(login.call_count, 7)
        self.assertEqual(driver.quit.call_count, 7)
        self.assertEqual(verify_routes.call_count, 5)
        self.assertEqual(
            [(call.args[1][0].path, call.args[1][0].allowed) for call in verify_routes.call_args_list],
            [
                ("/shares/", True),
                ("/shares/", True),
                ("/shares/", True),
                ("/shares/", True),
                ("/syncthing/", True),
            ],
        )
        self.assertEqual(peer_request.call_count, 6)
        admin_paths = [call.args[1] for call in request.call_args_list[2:6]]
        self.assertEqual(
            admin_paths,
            [
                "/shares/users/post-a/isolation-e2e.txt",
                "/shares/users/post-a/isolation-e2e.txt",
                "/shares/users/post-b/isolation-e2e.txt",
                "/shares/users/post-b/isolation-e2e.txt",
            ],
        )
        self.assertEqual(
            [call.kwargs.get("replace", False) for call in request.call_args_list],
            [False, False, False, True, False, True, False, False, False, False],
        )

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

    def test_capability_routes_omit_ai_when_the_profile_disables_it(self) -> None:
        self.assertNotIn("ai", self.authz.capability_routes(ai_enabled=False))

    def test_capability_routes_include_ai_when_the_profile_enables_it(self) -> None:
        self.assertEqual(self.authz.capability_routes(ai_enabled=True)["ai"], "/ai/")

    def test_administrator_assigns_application_capabilities_through_authentik_session(self) -> None:
        driver = mock.MagicMock()
        driver.execute_async_script.return_value = {"ok": True, "assigned": 3}
        groups = [
            "application.copyparty.files",
            "application.syncthing.access",
            "application.vaultwarden.access",
        ]
        with (
            mock.patch.object(self.authz, "browser", return_value=driver),
            mock.patch.object(self.authz, "login") as login,
        ):
            self.authz.assign_application_capabilities("https://nas-test.local", "nasadmin", "secret", "alice", groups)

        login.assert_called_once_with(driver, "https://nas-test.local", "nasadmin", "secret", "/identity/if/user/")
        self.assertIn("X-Authentik-Csrf", driver.execute_async_script.call_args.args[0])
        self.assertIn("remove_user", driver.execute_async_script.call_args.args[0])
        self.assertEqual(driver.execute_async_script.call_args.args[1:], ("alice", groups))
        driver.quit.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
