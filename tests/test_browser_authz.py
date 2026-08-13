from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import types
import unittest
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
            first_browser.assert_called_once_with("https://localhost:9092", "admin", "operator-secret")

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


if __name__ == "__main__":
    unittest.main()
