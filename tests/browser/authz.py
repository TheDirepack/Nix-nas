#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import stat
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterator

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait


@dataclass(frozen=True)
class RouteExpectation:
    path: str
    allowed: bool


def browser() -> webdriver.Chrome:
    from selenium.webdriver.chrome.service import Service

    options = webdriver.ChromeOptions()
    chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    chromedriver = shutil.which("chromedriver")
    if not chromium or not chromedriver:
        raise RuntimeError("The VM browser suite requires packaged chromium and chromedriver binaries")
    options.binary_location = chromium
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    for argument in [
        "--headless=new",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--ignore-certificate-errors",
        "--window-size=1280,900",
    ]:
        options.add_argument(argument)
    return webdriver.Chrome(service=Service(executable_path=chromedriver), options=options)


def search_roots(driver: webdriver.Chrome) -> Iterator[Any]:
    roots: list[Any] = [driver]
    for root in roots:
        yield root
        try:
            children = root.find_elements(By.CSS_SELECTOR, "*")
        except WebDriverException:
            continue
        for child in children:
            try:
                shadow_root = child.shadow_root
            except WebDriverException:
                continue
            roots.append(shadow_root)


def first(driver: webdriver.Chrome, selectors: list[str]) -> Any:
    for root in search_roots(driver):
        for selector in selectors:
            try:
                element = root.find_element(By.CSS_SELECTOR, selector)
                if element.is_displayed():
                    return element
            except (NoSuchElementException, WebDriverException):
                pass
    raise NoSuchElementException(", ".join(selectors))


def login_form_visible(driver: webdriver.Chrome) -> bool:
    try:
        return any(element.is_displayed() for element in driver.find_elements(By.CSS_SELECTOR, "#login-user-input"))
    except WebDriverException:
        # Authentik/Cockpit can replace the login form while the redirect is
        # completing; let WebDriverWait re-query the new document instead of
        # treating that normal transition as a test failure.
        return True


def button_with_text(driver: webdriver.Chrome, label: str) -> Any:
    for element in driver.find_elements(By.TAG_NAME, "button"):
        try:
            if element.is_displayed() and element.text.strip() == label:
                return element
        except WebDriverException:
            continue
    return None


VIEWPORTS = ((320, 720), (768, 900), (1280, 900), (1920, 1080))


def expected_cockpit_shell_entry(entry: dict[str, Any]) -> bool:
    message = str(entry.get("message", ""))
    return ("/favicon.ico" in message and "404" in message) or (
        "/console/cockpit/login" in message and "401" in message
    )


def verify_rendering_quality(driver: webdriver.Chrome, label: str) -> None:
    failures: list[dict[str, Any]] = []
    for width, height in VIEWPORTS:
        driver.set_window_size(width, height)
        WebDriverWait(driver, 20).until(
            lambda current: current.execute_script("return document.readyState") in {"interactive", "complete"}
        )
        result = driver.execute_script(
            """
            const viewport = document.documentElement.clientWidth;
            const visible = element => {
              const style = getComputedStyle(element);
              const rect = element.getBoundingClientRect();
              return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
            };
            const interactive = Array.from(document.querySelectorAll(
              'a[href],button,input,select,textarea,[role="button"],[role="link"]'
            )).filter(visible);
            const overflow = interactive.flatMap(element => {
              const rect = element.getBoundingClientRect();
              if (rect.left < -1 || rect.right > viewport + 1) {
                return [{tag: element.tagName, text: (element.innerText || element.getAttribute('aria-label') || '').slice(0, 80), left: rect.left, right: rect.right}];
              }
              return [];
            });
            const ids = Array.from(document.querySelectorAll('[id]')).map(element => element.id).filter(Boolean);
            const duplicates = [...new Set(ids.filter((value, index) => ids.indexOf(value) !== index))];
            return {
              viewport,
              documentWidth: document.documentElement.scrollWidth,
              bodyWidth: document.body ? document.body.scrollWidth : 0,
              overflow,
              duplicates,
            };
            """
        )
        if result["documentWidth"] > result["viewport"] + 1 or result["bodyWidth"] > result["viewport"] + 1:
            failures.append({"viewport": [width, height], "reason": "horizontal-overflow", **result})
        if result["overflow"]:
            failures.append({"viewport": [width, height], "reason": "interactive-control-overflow", **result})
        if result["duplicates"]:
            failures.append({"viewport": [width, height], "reason": "duplicate-dom-ids", **result})
    try:
        severe = [
            entry
            for entry in driver.get_log("browser")
            if entry.get("level") == "SEVERE" and not expected_cockpit_shell_entry(entry)
        ]
    except (WebDriverException, ValueError):
        severe = []
    if severe:
        failures.append({"reason": "browser-console-errors", "entries": severe[-20:]})
    if failures:
        raise RuntimeError(f"{label} rendering validation failed: {json.dumps(failures, indent=2, sort_keys=True)}")


def login(driver: webdriver.Chrome, origin: str, username: str, password: str) -> None:
    driver.get(origin + "/")
    wait = WebDriverWait(driver, 60)
    wait.until(lambda current: "/identity/" in current.current_url)
    username_input = wait.until(
        lambda current: first(
            current,
            [
                'input[name="uid_field"]',
                'input[name="username"]',
                'input[autocomplete="username"]',
                'input[type="email"]',
                'input[type="text"]',
            ],
        )
    )
    username_input.clear()
    username_input.send_keys(username)
    first(driver, ['button[type="submit"]', 'input[type="submit"]']).click()
    password_input = wait.until(
        lambda current: first(
            current,
            ['input[name="password"]', 'input[autocomplete="current-password"]', 'input[type="password"]'],
        )
    )
    password_input.send_keys(password)
    first(driver, ['button[type="submit"]', 'input[type="submit"]']).click()
    wait.until(lambda current: "/identity/if/flow/" not in current.current_url)


def cockpit_login(driver: webdriver.Chrome, origin: str, username: str, password: str) -> None:
    cockpit_root = origin.rstrip("/") + "/console/"
    driver.get(cockpit_root)
    wait = WebDriverWait(driver, 60)
    username_input = wait.until(
        lambda current: first(
            current,
            [
                "#login-user-input",
                'input[name="user"]',
                'input[autocomplete="username"]',
            ],
        )
    )
    username_input.clear()
    username_input.send_keys(username)
    password_input = first(
        driver,
        [
            "#login-password-input",
            'input[name="password"]',
            'input[autocomplete="current-password"]',
        ],
    )
    password_input.send_keys(password)
    first(driver, ["#login-button", 'button[type="submit"]']).click()
    wait.until(
        lambda current: (
            current.current_url.startswith(origin.rstrip("/") + "/console/") and not login_form_visible(current)
        )
    )


def browser_diagnostics(driver: webdriver.Chrome) -> dict[str, Any]:
    try:
        body_text = driver.find_element(By.TAG_NAME, "body").text
    except WebDriverException as error:
        body_text = f"<unable to read body: {error}>"
    try:
        console = driver.get_log("browser")[-20:]
    except (WebDriverException, ValueError):
        console = []
    return {
        "url": driver.current_url,
        "title": driver.title,
        "body": body_text[:5000],
        "console": console,
    }


def wait_for_page_text(driver: webdriver.Chrome, wait: WebDriverWait, text: str, label: str) -> None:
    try:
        wait.until(lambda current: text in current.page_source)
    except TimeoutException as error:
        details = json.dumps(browser_diagnostics(driver), indent=2, sort_keys=True)
        raise RuntimeError(f"{label} did not render {text!r}:\n{details}") from error


def rendered_text(driver: webdriver.Chrome) -> str:
    """Return document text, including open shadow roots and same-origin frames."""
    try:
        return str(
            driver.execute_script(
                """
                const collect = root => {
                  let value = root.body?.innerText || root.innerText || '';
                  value += '\\n' + (root.body?.textContent || root.textContent || '');
                  for (const element of root.querySelectorAll('*')) {
                    if (element.shadowRoot) value += '\\n' + collect(element.shadowRoot);
                    if (element.tagName === 'IFRAME') {
                      try {
                        if (element.contentDocument) value += '\\n' + collect(element.contentDocument);
                      } catch (_error) {
                        // Cross-origin frames are intentionally inaccessible.
                      }
                    }
                  }
                  return value;
                };
                return collect(document);
                """
            )
        )
    except WebDriverException:
        return driver.page_source


def verify_cockpit_react_interactions(origin: str, username: str, password: str) -> None:
    driver = browser()
    try:
        cockpit_login(driver, origin, username, password)
        driver.get(origin.rstrip("/") + "/console/cockpit/@localhost/nas/index.html")
        wait = WebDriverWait(driver, 90)
        wait_for_page_text(driver, wait, "NAS Overview", "Cockpit NAS page")
        wait_for_page_text(driver, wait, "Maintenance actions", "Cockpit NAS page")
        wait.until(lambda current: button_with_text(current, "Refresh")).click()
        wait.until(lambda current: button_with_text(current, "Run system health checks")).click()
        wait.until(lambda current: "Confirm maintenance action" in current.page_source)
        cancel = wait.until(lambda current: button_with_text(current, "Cancel"))
        cancel.click()
        wait.until(lambda current: "Confirm maintenance action" not in current.page_source)
        verify_rendering_quality(driver, "Cockpit NAS page")
    finally:
        driver.quit()


def fetch_status(driver: webdriver.Chrome, path: str) -> dict[str, Any]:
    return driver.execute_async_script(
        """
        const done = arguments[arguments.length - 1];
        fetch(arguments[0], {credentials: 'include', redirect: 'follow'})
          .then(response => done({status: response.status, url: response.url}))
          .catch(error => done({status: 0, url: '', error: String(error)}));
        """,
        path,
    )


def verify_routes(driver: webdriver.Chrome, expectations: list[RouteExpectation]) -> None:
    failures: list[dict[str, Any]] = []
    for expectation in expectations:
        result = fetch_status(driver, expectation.path)
        denied = result["status"] in {401, 403} or "/identity/if/flow/" in result["url"]
        if denied == expectation.allowed:
            failures.append({"path": expectation.path, "expectedAllowed": expectation.allowed, **result})
    if failures:
        raise RuntimeError(json.dumps(failures, indent=2, sort_keys=True))


def verify_settings_form(driver: webdriver.Chrome, origin: str) -> None:
    driver.get(origin + "/identity/if/flow/nas-user-settings/")
    wait = WebDriverWait(driver, 60)
    try:
        wait.until(lambda current: "Syncthing" in rendered_text(current))
        first(
            driver,
            [
                'textarea[name="attributes.nasSyncthingDevices"]',
                'textarea[aria-label*="Syncthing"]',
                "textarea",
            ],
        )
    except (NoSuchElementException, TimeoutException) as error:
        details = json.dumps(browser_diagnostics(driver), indent=2, sort_keys=True)
        raise RuntimeError(
            f"Authentik NAS user-settings flow did not render the Syncthing field:\n{details}"
        ) from error


def native_share_response(origin: str) -> dict[str, Any]:
    url = origin.rstrip("/") + "/share/not-a-real-token"
    request = urllib.request.Request(url, headers={"Accept": "text/html"})
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            return {"status": response.status, "url": response.geturl()}
    except urllib.error.HTTPError as response:
        return {"status": response.code, "url": response.geturl()}
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        raise RuntimeError(f"CopyParty native share route request failed: {error}") from error


def verify_native_share_route(_driver: webdriver.Chrome, origin: str) -> None:
    # An invalid native share can execute CopyParty's own error-page script;
    # inspect the response with a non-browser client so that page cannot run.
    result = native_share_response(origin)
    if "/identity/if/flow/" in result["url"]:
        raise RuntimeError("CopyParty native share route was intercepted by Authentik")


def verify_no_identity_markup_injection(driver: webdriver.Chrome, username: str) -> None:
    if username != "alice":
        return
    result = driver.execute_script(
        """
        return {
          injectedImage: Boolean(document.querySelector('img[src="x"]')),
          executionMarker: document.body?.dataset?.nasXss || null,
        };
        """
    )
    if result["injectedImage"] or result["executionMarker"]:
        raise RuntimeError(f"portal executed identity-derived HTML: {result!r}")
    hostile_display_name = "<img src=x onerror=document.body.dataset.nasXss=1>"
    text = rendered_text(driver)
    if hostile_display_name not in text:
        raise RuntimeError(
            "portal did not render the hostile identity display name as inert text: "
            f"url={driver.current_url!r} text={text[:2000]!r}"
        )


def run_account(
    origin: str, username: str, password: str, expectations: list[RouteExpectation], settings: bool
) -> None:
    driver = browser()
    try:
        login(driver, origin, username, password)
        verify_rendering_quality(driver, f"portal for {username}")
        verify_no_identity_markup_injection(driver, username)
        verify_routes(driver, expectations)
        verify_native_share_route(driver, origin)
        if settings:
            verify_settings_form(driver, origin)
    finally:
        driver.quit()


def read_secret(path: str) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Password path is not a regular file: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"Password file is group/world accessible: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
            value = handle.read(4098)
    finally:
        os.close(descriptor)
    if len(value.encode("utf-8")) > 4097:
        raise ValueError(f"Password file is too large: {path}")
    if value.endswith("\n"):
        value = value[:-1]
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError(f"Invalid one-line password file: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="https://nas-test.local")
    parser.add_argument("--cockpit-origin", default="https://localhost:9092")
    parser.add_argument("--cockpit-password-file", required=True)
    parser.add_argument("--operator-password-file", required=True)
    parser.add_argument("--alice-password-file", required=True)
    parser.add_argument("--baseline-password-file", required=True)
    args = parser.parse_args()
    cockpit_password = read_secret(args.cockpit_password_file)
    operator_password = read_secret(args.operator_password_file)
    alice_password = read_secret(args.alice_password_file)
    baseline_password = read_secret(args.baseline_password_file)
    verify_cockpit_react_interactions(args.cockpit_origin, "admin", cockpit_password)
    capability_routes = {
        "files": "/shares/",
        "webdav": "/dav/",
        "ai": "/ai/",
        "vault": "/vault/",
        "syncthing": "/settings/syncthing",
    }
    common_allowed = [
        RouteExpectation(capability_routes["files"], True),
        RouteExpectation(capability_routes["vault"], True),
    ]
    run_account(
        args.origin,
        "operator",
        operator_password,
        common_allowed
        + [
            RouteExpectation(capability_routes["webdav"], True),
            RouteExpectation(capability_routes["syncthing"], True),
            RouteExpectation("/syncthing/", True),
            RouteExpectation(capability_routes["ai"], True),
            RouteExpectation("/alerts/", True),
            RouteExpectation("/victoriametrics/", True),
        ],
        True,
    )
    run_account(
        args.origin,
        "alice",
        alice_password,
        common_allowed
        + [
            RouteExpectation(capability_routes["webdav"], False),
            RouteExpectation(capability_routes["syncthing"], True),
            RouteExpectation("/syncthing/", False),
            RouteExpectation(capability_routes["ai"], False),
            RouteExpectation("/alerts/", False),
            RouteExpectation("/victoriametrics/", False),
        ],
        False,
    )
    run_account(
        args.origin,
        "baseline",
        baseline_password,
        [RouteExpectation(path, False) for path in capability_routes.values()]
        + [RouteExpectation("/syncthing/", False)],
        False,
    )
    print("browser authorization, rendering, layout, and console checks ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
