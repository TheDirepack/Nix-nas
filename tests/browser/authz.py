#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Iterator, cast

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait


@dataclass(frozen=True)
class RouteExpectation:
    path: str
    allowed: bool
    allowed_redirect_prefix: str | None = None


def browser() -> webdriver.Chrome:
    from selenium.webdriver.chrome.service import Service

    options = webdriver.ChromeOptions()
    chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    chromedriver = shutil.which("chromedriver")
    if not chromium or not chromedriver:
        raise RuntimeError("The VM browser suite requires packaged chromium and chromedriver binaries")
    options.binary_location = chromium
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    arguments = [
        "--headless=new",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--ignore-certificate-errors",
        "--window-size=1280,900",
    ]
    browser_address = os.environ.get("NAS_BROWSER_HOST_ADDRESS", "").strip()
    if browser_address:
        # The VM's public hostname is an isolated test alias, not a DNS
        # record. Pin it in Chromium to the address of the callback listener
        # so redirects and callback requests use the same endpoint.
        arguments.append(f"--host-resolver-rules=MAP nas-test.local {browser_address}")
    for argument in arguments:
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


def first_maintenance_action(driver: webdriver.Chrome) -> Any:
    for element in driver.find_elements(By.CSS_SELECTOR, ".nas-actions button"):
        try:
            if element.is_displayed():
                return element
        except WebDriverException:
            continue
    return None


VIEWPORTS = ((320, 720), (768, 900), (1280, 900), (1920, 1080))
ALLOWED_ROUTE_RETRY_ATTEMPTS = 30
COCKPIT_ROUTE_RETRY_ATTEMPTS = 3
COCKPIT_SESSION_ATTEMPTS = 2
COCKPIT_TRANSIENT_HTTP_ERRORS = tuple(f"HTTP ERROR {status}" for status in (401, 403, 502, 503))
AUTHENTIK_LOGIN_ATTEMPTS = 2
AUTHENTIK_TRANSIENT_HTTP_STATUSES = (502, 503, 504)


def expected_cockpit_shell_entry(entry: dict[str, Any]) -> bool:
    message = str(entry.get("message", ""))
    return ("/favicon.ico" in message and "404" in message) or (
        "/console/cockpit/login" in message and "401" in message
    )


def discard_browser_log(driver: webdriver.Chrome) -> None:
    """Discard diagnostics produced by the unauthenticated login shell."""
    try:
        driver.get_log("browser")
    except (WebDriverException, ValueError):
        pass


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
              const rendered = element.checkVisibility
                ? element.checkVisibility({checkOpacity: true, checkVisibilityCSS: true})
                : style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
              return rendered && rect.width > 0 && rect.height > 0;
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
            const visibleOverflow = [];
            const scanVisibleOverflow = (root, rootViewport) => {
              for (const element of root.querySelectorAll('*')) {
                const rect = element.getBoundingClientRect();
                if (visible(element) && rect.right > rootViewport + 1) {
                  visibleOverflow.push({
                    tag: element.tagName,
                    text: (element.innerText || element.getAttribute('aria-label') || '').trim().slice(0, 80),
                    left: rect.left,
                    right: rect.right,
                  });
                }
                if (element.shadowRoot) scanVisibleOverflow(element.shadowRoot, rootViewport);
                if (element.tagName === 'IFRAME') {
                  try {
                    if (element.contentDocument) {
                      scanVisibleOverflow(element.contentDocument, element.contentDocument.documentElement.clientWidth);
                    }
                  } catch (_error) {
                    // Cross-origin frames are intentionally inaccessible.
                  }
                }
              }
            };
            scanVisibleOverflow(document, viewport);
            const ids = Array.from(document.querySelectorAll('[id]')).map(element => element.id).filter(Boolean);
            const duplicates = [...new Set(ids.filter((value, index) => ids.indexOf(value) !== index))];
            return {
              viewport,
              documentWidth: document.documentElement.scrollWidth,
              bodyWidth: document.body ? document.body.scrollWidth : 0,
              overflow,
              visibleOverflow: visibleOverflow.slice(0, 20),
              duplicates,
            };
            """
        )
        document_overflow = (
            result["documentWidth"] > result["viewport"] + 1 or result["bodyWidth"] > result["viewport"] + 1
        )
        if document_overflow and result["visibleOverflow"]:
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


def authenticated_destination_loaded(current: webdriver.Chrome, public_origin: str) -> bool:
    url = current.current_url
    if "/identity/if/flow/" in url or "/outpost.goauthentik.io/callback" in url:
        return False
    if url != public_origin and not url.startswith(public_origin + "/"):
        return False
    if current.execute_script("return document.readyState") not in {"interactive", "complete"}:
        return False
    if urllib.parse.urlsplit(url).path == "/identity/if/user/":
        return "My applications" in rendered_text(current)
    return True


def _login_once(driver: webdriver.Chrome, origin: str, username: str, password: str, path: str) -> None:
    driver.get(origin.rstrip("/") + path)
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
    # Authentik probes its current-user endpoint while the login shell is
    # unauthenticated. That expected 403 must not be carried into the
    # authenticated portal rendering assertions below.
    discard_browser_log(driver)
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
    public_origin = origin.rstrip("/")
    wait.until(lambda current: authenticated_destination_loaded(current, public_origin))


def transient_authentik_login_error(diagnostics: dict[str, Any]) -> bool:
    if urllib.parse.urlsplit(str(diagnostics.get("url", ""))).path != "/identity/if/flow/default-authentication-flow/":
        return False
    if "Response returned an error code" not in str(diagnostics.get("body", "")):
        return False
    endpoint = "/identity/api/v3/flows/executor/default-authentication-flow/"
    for entry in diagnostics.get("console", []):
        message = str(entry.get("message", ""))
        if endpoint not in message:
            continue
        if any(
            f"status of {status}" in message or f"{status} POST" in message
            for status in AUTHENTIK_TRANSIENT_HTTP_STATUSES
        ):
            return True
    return False


def reset_browser_session(driver: webdriver.Chrome, origin: str) -> None:
    driver.get("about:blank")
    driver.execute_cdp_cmd("Network.clearBrowserCookies", {})
    driver.execute_cdp_cmd(
        "Storage.clearDataForOrigin",
        {"origin": origin.rstrip("/"), "storageTypes": "all"},
    )


def login(driver: webdriver.Chrome, origin: str, username: str, password: str, path: str = "/") -> None:
    for attempt in range(AUTHENTIK_LOGIN_ATTEMPTS):
        try:
            _login_once(driver, origin, username, password, path)
            return
        except TimeoutException as error:
            diagnostics = browser_diagnostics(driver)
            if attempt + 1 < AUTHENTIK_LOGIN_ATTEMPTS and transient_authentik_login_error(diagnostics):
                reset_browser_session(driver, origin)
                time.sleep(1)
                continue
            details = json.dumps(diagnostics, indent=2, sort_keys=True)
            raise RuntimeError(f"Authentik browser login did not complete for {username!r}:\n{details}") from error


def assign_application_capabilities(
    origin: str,
    administrator: str,
    password: str,
    username: str,
    groups: list[str],
) -> None:
    driver = browser()
    try:
        login(driver, origin, administrator, password, "/identity/if/user/")
        result = driver.execute_async_script(
            """
            const [username, groupNames, done] = arguments;
            const csrf = document.cookie
              .split('; ')
              .find(cookie => cookie.startsWith('authentik_csrf='))
              ?.split('=', 2)[1];
            const request = async (path, options = {}) => {
              const response = await fetch(`/identity/api/v3/${path}`, {
                credentials: 'same-origin',
                ...options,
              });
              if (!response.ok) {
                throw new Error(`${options.method || 'GET'} ${path}: HTTP ${response.status}`);
              }
              return response.status === 204 ? null : response.json();
            };
            (async () => {
              if (!csrf) throw new Error('Authentik CSRF cookie is unavailable');
              const users = await request(`core/users/?username=${encodeURIComponent(username)}`);
              const user = users.results.find(candidate => candidate.username === username);
              if (!user) throw new Error(`Authentik user ${username} was not found`);
              const groups = await request('core/groups/?ordering=name&page_size=100');
              const capabilityGroups = groups.results.filter(group => group.attributes?.nasManagedCapability === true);
              const requested = new Set(groupNames);
              for (const groupName of requested) {
                if (!capabilityGroups.some(group => group.name === groupName)) {
                  throw new Error(`Authentik group ${groupName} was not found`);
                }
              }
              const current = new Set((user.groups || []).map(String));
              for (const group of capabilityGroups) {
                const assigned = current.has(String(group.pk));
                const desired = requested.has(group.name);
                if (assigned === desired) continue;
                await request(`core/groups/${encodeURIComponent(group.pk)}/${desired ? 'add_user' : 'remove_user'}/`, {
                  method: 'POST',
                  headers: {'Content-Type': 'application/json', 'X-Authentik-Csrf': decodeURIComponent(csrf)},
                  body: JSON.stringify({pk: user.num_pk ?? user.pk}),
                });
              }
              done({ok: true, assigned: groupNames.length});
            })().catch(error => done({ok: false, error: String(error)}));
            """,
            username,
            groups,
        )
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise RuntimeError(f"Authentik capability assignment failed: {result}")
    finally:
        driver.quit()


def cockpit_destination_loaded(driver: webdriver.Chrome, origin: str) -> bool:
    return (
        driver.current_url.startswith(origin.rstrip("/") + "/console/")
        and not login_form_visible(driver)
        and not any(marker in driver.page_source for marker in COCKPIT_TRANSIENT_HTTP_ERRORS)
    )


def cockpit_login(driver: webdriver.Chrome, origin: str, username: str, password: str) -> None:
    cockpit_root = origin.rstrip("/") + "/console/"
    wait = WebDriverWait(driver, 60)
    for session_attempt in range(COCKPIT_SESSION_ATTEMPTS):
        login(driver, origin, username, password)
        persistent_403 = True
        for route_attempt in range(COCKPIT_ROUTE_RETRY_ATTEMPTS):
            driver.get(cockpit_root)
            wait.until(lambda current: current.current_url.startswith(cockpit_root) and not login_form_visible(current))
            if cockpit_destination_loaded(driver, origin):
                return
            persistent_403 = persistent_403 and "HTTP ERROR 403" in driver.page_source
            if not any(marker in driver.page_source for marker in COCKPIT_TRANSIENT_HTTP_ERRORS):
                break
            if route_attempt + 1 < COCKPIT_ROUTE_RETRY_ATTEMPTS:
                time.sleep(1)
        if not persistent_403 or session_attempt + 1 >= COCKPIT_SESSION_ATTEMPTS:
            break
        print("VM-BROWSER-RECOVERY: restarting persistently denied Cockpit session", file=sys.stderr, flush=True)
        reset_browser_session(driver, origin)
        time.sleep(1)
    details = json.dumps(browser_diagnostics(driver), indent=2, sort_keys=True)
    raise RuntimeError(f"Cockpit route did not become ready for {username!r}:\n{details}")


def callback_return_matches(expected_path: str, returned_path: str) -> bool:
    """Allow the portal's canonical trailing-slash redirect after login."""
    canonical_path = expected_path if expected_path.endswith("/") else expected_path + "/"
    if returned_path in {expected_path, canonical_path}:
        return True
    # Cockpit redirects an authenticated console visit to its default page
    # inside the console subtree; the gate still returned the user to the
    # requested application.
    if canonical_path == "/console/" and returned_path.startswith("/console/"):
        return True
    return False


def verify_callback_return_paths(origin: str, username: str, password: str, paths: list[str]) -> None:
    for path in paths:
        driver = browser()
        try:
            browser_step(driver, f"Callback return ({path})", lambda: login(driver, origin, username, password, path))
            returned_path = urllib.parse.urlsplit(driver.current_url).path
            if not callback_return_matches(path, returned_path):
                raise RuntimeError(f"Authentik callback returned {returned_path!r}, expected {path!r}")
        finally:
            driver.quit()


def verify_launcher_opens_console(origin: str, username: str, password: str) -> None:
    driver = browser()
    try:
        browser_step(driver, f"Launcher login ({username})", lambda: login(driver, origin, username, password))
        wait = WebDriverWait(driver, 60)
        launcher_link = wait.until(lambda current: first(current, ['a[href="/console/"]', 'a[href$="/console/"]']))
        browser_step(driver, "Launcher opens Cockpit", launcher_link.click)
        wait.until(
            lambda current: callback_return_matches("/console/", urllib.parse.urlsplit(current.current_url).path)
        )
    finally:
        driver.quit()


def safe_browser_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


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
        "url": safe_browser_url(driver.current_url),
        "title": driver.title,
        "body": body_text[:5000],
        "console": console,
    }


def browser_step(driver: webdriver.Chrome, label: str, operation: Callable[[], None]) -> None:
    print(f"VM-BROWSER-STAGE-START: {label}", file=sys.stderr, flush=True)
    try:
        operation()
    except Exception as error:
        diagnostics = json.dumps(browser_diagnostics(driver), default=str, indent=2, sort_keys=True)
        print(
            f"VM-BROWSER-STAGE-FAIL: {label}: {type(error).__name__}: {error}\nVM-BROWSER-DIAGNOSTICS: {diagnostics}",
            file=sys.stderr,
            flush=True,
        )
        raise
    print(f"VM-BROWSER-STAGE-DONE: {label}", file=sys.stderr, flush=True)


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
        browser_step(driver, f"Cockpit login ({username})", lambda: cockpit_login(driver, origin, username, password))

        def verify_page() -> None:
            driver.get(origin.rstrip("/") + "/console/cockpit/@localhost/nas/index.html")
            wait = WebDriverWait(driver, 90)
            wait_for_page_text(driver, wait, "NAS Overview", "Cockpit NAS page")
            wait_for_page_text(driver, wait, "Protected services:", "Cockpit NAS page")

        browser_step(driver, "Cockpit NAS page", verify_page)

        def verify_actions() -> None:
            wait = WebDriverWait(driver, 90)
            wait.until(lambda current: current.find_element(By.CSS_SELECTOR, "a[href='#/operations']")).click()
            wait_for_page_text(driver, wait, "Operation coordinator", "Cockpit operations page")
            wait.until(first_maintenance_action).click()
            wait.until(lambda current: "Confirm maintenance action" in current.page_source)
            cancel = wait.until(lambda current: button_with_text(current, "Cancel"))
            cancel.click()
            wait.until(lambda current: "Confirm maintenance action" not in current.page_source)

        browser_step(driver, "Cockpit maintenance actions", verify_actions)
        browser_step(
            driver, "Cockpit rendering and console", lambda: verify_rendering_quality(driver, "Cockpit NAS page")
        )
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


def fetch_outpost_identity(driver: webdriver.Chrome, path: str) -> dict[str, Any]:
    return driver.execute_async_script(
        """
        const done = arguments[arguments.length - 1];
        fetch('/outpost.goauthentik.io/auth/caddy', {
          credentials: 'include',
          headers: {
            'X-Original-URL': new URL(arguments[0], window.location.origin).href,
            'X-Forwarded-Host': window.location.host,
            'X-Forwarded-Proto': window.location.protocol.slice(0, -1),
            'X-Forwarded-Uri': arguments[0],
          },
          redirect: 'manual',
        }).then(response => done({
          status: response.status,
          username: response.headers.get('X-Authentik-Username') || '',
          groups: response.headers.get('X-Authentik-Groups') || '',
          entitlements: response.headers.get('X-Authentik-Entitlements') || '',
        })).catch(error => done({status: 0, error: String(error)}));
        """,
        path,
    )


def verify_routes(driver: webdriver.Chrome, expectations: list[RouteExpectation]) -> None:
    def matches(expectation: RouteExpectation, result: dict[str, Any]) -> bool:
        status = int(result.get("status", 0))
        url = str(result.get("url", ""))
        url_path = urllib.parse.urlsplit(url).path
        identity_flow = "/identity/if/flow/" in url_path
        if expectation.allowed:
            expected_path = expectation.path if expectation.path.endswith("/") else expectation.path + "/"
            return (
                200 <= status < 400
                and (not identity_flow or expectation.allowed_redirect_prefix is not None)
                and (
                    url_path.startswith(expectation.allowed_redirect_prefix)
                    if expectation.allowed_redirect_prefix is not None
                    else url_path in {expectation.path, expected_path} or url_path.startswith(expected_path)
                )
            )
        return status in {401, 403} and not identity_flow

    failures: list[dict[str, Any]] = []
    for expectation in expectations:
        result = fetch_status(driver, expectation.path)
        for _ in range(ALLOWED_ROUTE_RETRY_ATTEMPTS):
            if matches(expectation, result):
                break
            # CopyParty creates the first IdP user lazily. Its first request
            # can race the configuration reload, so retry only transient
            # failures for routes that should be reachable. The reload can
            # involve Authentik and indexing, so keep this bounded but longer
            # than the usual one-second proxy retry window.
            if not expectation.allowed or result.get("status") not in {401, 403, 502, 503}:
                break
            time.sleep(1)
            result = fetch_status(driver, expectation.path)
        if not matches(expectation, result):
            failure = {"path": expectation.path, "expectedAllowed": expectation.allowed, **result}
            if expectation.allowed and int(result.get("status", 0)) == 403:
                failure["outpostIdentity"] = fetch_outpost_identity(driver, expectation.path)
            failures.append(failure)
    if failures:
        raise RuntimeError(json.dumps(failures, indent=2, sort_keys=True))


def fetch_request(
    driver: webdriver.Chrome,
    path: str,
    method: str,
    body: str | None = None,
    *,
    replace: bool = False,
) -> dict[str, Any]:
    return driver.execute_async_script(
        """
        const done = arguments[arguments.length - 1];
        const options = {method: arguments[1], credentials: 'include', redirect: 'follow', headers: {}};
        if (arguments[2] !== null) {
          options.body = arguments[2];
          options.headers['Content-Type'] = 'text/plain';
        }
        if (arguments[3]) options.headers.Replace = '1';
        fetch(arguments[0], options)
          .then(async response => done({status: response.status, url: response.url, body: await response.text()}))
          .catch(error => done({status: 0, url: '', body: '', error: String(error)}));
        """,
        path,
        method,
        body,
        replace,
    )


def verify_personal_file_operations(driver: webdriver.Chrome, username: str) -> None:
    path = f"/shares/users/{urllib.parse.quote(username, safe='')}/browser-e2e.txt"
    content = f"browser-e2e-{username}"
    written = fetch_request(driver, path, "PUT", content)
    if int(written.get("status", 0)) not in {200, 201, 204}:
        raise RuntimeError(f"personal file upload failed: {written!r}")
    downloaded = fetch_request(driver, path, "GET")
    if int(downloaded.get("status", 0)) != 200 or downloaded.get("body") != content:
        raise RuntimeError(f"personal file download failed: {downloaded!r}")
    deleted = fetch_request(driver, path, "DELETE")
    if int(deleted.get("status", 0)) not in {200, 202, 204}:
        raise RuntimeError(f"personal file deletion failed: {deleted!r}")


def verify_cross_user_file_access_blocked(driver: webdriver.Chrome, origin: str, username: str) -> None:
    path = f"/shares/users/{urllib.parse.quote(username, safe='')}/isolation-e2e.txt"
    for method, body in (("GET", None), ("PUT", "cross-user-overwrite"), ("DELETE", None)):
        result = authenticated_https_request(driver, origin, path, method, body)
        if int(result.get("status", 0)) not in {401, 403, 404}:
            raise RuntimeError(f"cross-user {method} unexpectedly succeeded: {result!r}")


def verify_administrator_syncthing_folders(driver: webdriver.Chrome, usernames: list[str]) -> None:
    result = fetch_request(driver, "/syncthing/rest/config/folders", "GET")
    if int(result.get("status", 0)) != 200:
        raise RuntimeError(f"administrator could not inspect Syncthing folders: {result!r}")
    try:
        folders = json.loads(str(result.get("body", "")))
    except json.JSONDecodeError as error:
        raise RuntimeError("Syncthing folder response was not JSON") from error
    by_id = {item.get("id"): item for item in folders if isinstance(item, dict)} if isinstance(folders, list) else {}
    device_sets: list[set[str]] = []
    for username in usernames:
        folder = by_id.get(f"nas-{username}-backup")
        expected_path = f"/tank/shares/users/{username}/syncthing"
        if not isinstance(folder, dict) or folder.get("path") != expected_path:
            raise RuntimeError(f"administrator did not see the isolated Syncthing folder for {username}: {folder!r}")
        devices = {
            str(device.get("deviceID"))
            for device in folder.get("devices", [])
            if isinstance(device, dict) and device.get("deviceID")
        }
        if not devices:
            raise RuntimeError(f"Syncthing folder for {username} has no assigned devices")
        device_sets.append(devices)
    if any(left & right for index, left in enumerate(device_sets) for right in device_sets[index + 1 :]):
        raise RuntimeError("isolated Syncthing folders share a user device")


def verify_copy_party_user_isolation(
    origin: str,
    administrator: tuple[str, str],
    accounts: list[tuple[str, str]],
) -> None:
    contents = {username: f"copy-party-isolation-{username}" for username, _password in accounts}
    for username, password in accounts:
        driver = browser()
        try:
            login(driver, origin, username, password)
            verify_routes(driver, [RouteExpectation("/shares/", True)])
            path = f"/shares/users/{urllib.parse.quote(username, safe='')}/isolation-e2e.txt"
            written = fetch_request(driver, path, "PUT", contents[username])
            if int(written.get("status", 0)) not in {200, 201, 204}:
                raise RuntimeError(f"personal isolation sentinel upload failed for {username}: {written!r}")
        finally:
            driver.quit()

    for attacker, password in accounts:
        for victim, _victim_password in accounts:
            if attacker == victim:
                continue
            driver = browser()
            try:
                login(driver, origin, attacker, password)
                verify_routes(driver, [RouteExpectation("/shares/", True)])
                verify_cross_user_file_access_blocked(driver, origin, victim)
            finally:
                driver.quit()

    admin_username, admin_password = administrator
    driver = browser()
    try:
        login(driver, origin, admin_username, admin_password)
        verify_routes(driver, [RouteExpectation("/syncthing/", True), RouteExpectation("/shares/admin/", True)])
        for username, _password in accounts:
            path = f"/shares/users/{urllib.parse.quote(username, safe='')}/isolation-e2e.txt"
            downloaded = fetch_request(driver, path, "GET")
            if int(downloaded.get("status", 0)) != 200 or downloaded.get("body") != contents[username]:
                raise RuntimeError(f"administrator could not read {username}'s personal file: {downloaded!r}")
            contents[username] = f"copy-party-administrator-update-{username}"
            written = fetch_request(driver, path, "PUT", contents[username], replace=True)
            if int(written.get("status", 0)) not in {200, 201, 204}:
                raise RuntimeError(f"administrator could not update {username}'s personal file: {written!r}")
    finally:
        driver.quit()

    for username, password in accounts:
        driver = browser()
        try:
            login(driver, origin, username, password)
            path = f"/shares/users/{urllib.parse.quote(username, safe='')}/isolation-e2e.txt"
            downloaded = fetch_request(driver, path, "GET")
            if int(downloaded.get("status", 0)) != 200 or downloaded.get("body") != contents[username]:
                raise RuntimeError(f"personal isolation sentinel changed for {username}: {downloaded!r}")
            deleted = fetch_request(driver, path, "DELETE")
            if int(deleted.get("status", 0)) not in {200, 202, 204}:
                raise RuntimeError(f"personal isolation sentinel deletion failed for {username}: {deleted!r}")
        finally:
            driver.quit()


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


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, **kwargs: Any) -> None:
        self._address = address
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        connection: Any = cast(Any, self)
        connection.sock = socket.create_connection((self._address, self.port), self.timeout, connection.source_address)
        if connection._tunnel_host:
            connection._tunnel()
        connection.sock = connection._context.wrap_socket(
            connection.sock,
            server_hostname=connection._tunnel_host or connection.host,
        )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, address: str, context: ssl.SSLContext) -> None:
        super().__init__(context=context)
        self._address = address
        self._tls_context = context

    def https_open(self, request: urllib.request.Request) -> Any:
        return self.do_open(
            lambda host, **kwargs: _PinnedHTTPSConnection(host, self._address, **kwargs),
            request,
            context=self._tls_context,
        )


def authenticated_https_request(
    driver: webdriver.Chrome,
    origin: str,
    path: str,
    method: str,
    body: str | None = None,
) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or not path.startswith("/"):
        raise ValueError("authenticated browser probe requires an HTTPS origin and root-relative path")
    address = os.environ.get("NAS_BROWSER_HOST_ADDRESS", "").strip() or parsed.hostname
    cookies = "; ".join(f"{cookie['name']}={cookie['value']}" for cookie in driver.get_cookies())
    headers = {"Host": parsed.netloc, "Cookie": cookies}
    payload = body.encode() if body is not None else None
    if payload is not None:
        headers["Content-Type"] = "text/plain"
    connection = _PinnedHTTPSConnection(
        parsed.hostname,
        address,
        port=parsed.port or 443,
        timeout=30,
        context=ssl._create_unverified_context(),
    )
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        response_body = response.read().decode(errors="replace")
        location = response.getheader("Location")
        response_url = (
            urllib.parse.urljoin(origin.rstrip("/") + path, location) if location else origin.rstrip("/") + path
        )
        return {"status": response.status, "url": response_url, "body": response_body}
    except (OSError, TimeoutError, http.client.HTTPException) as error:
        raise RuntimeError(f"authenticated browser probe failed: {error}") from error
    finally:
        connection.close()


def native_share_response(origin: str) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(origin)
    headers = {"Accept": "text/html"}
    request_origin = origin.rstrip("/")
    browser_address = os.environ.get("NAS_BROWSER_HOST_ADDRESS", "").strip()
    opener: urllib.request.OpenerDirector | None = None
    # The VM browser harness supplies the callback listener address for both
    # Chromium and urllib. Preserve the original Host header for Caddy routing.
    if parsed.hostname == "nas-test.local" and browser_address:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _PinnedHTTPSHandler(browser_address, ssl._create_unverified_context()),
        )
        headers["Host"] = parsed.netloc
    request = urllib.request.Request(request_origin + "/share/not-a-real-token", headers=headers)
    context = ssl._create_unverified_context()
    try:
        response_context = (
            opener.open(request, timeout=30) if opener else urllib.request.urlopen(request, context=context, timeout=30)
        )
        with response_context as response:
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


def verify_no_identity_markup_injection(
    driver: webdriver.Chrome,
    username: str,
    *,
    require_hostile_display_name: bool = False,
) -> None:
    if username != "alice":
        return
    result = driver.execute_script(
        """
        const result = {injectedImage: false, executionMarker: null};
        const scan = root => {
          result.injectedImage ||= Boolean(root.querySelector('img[src="x"]'));
          result.executionMarker ||= root.body?.dataset?.nasXss || null;
          for (const element of root.querySelectorAll('*')) {
            if (element.shadowRoot) scan(element.shadowRoot);
            if (element.tagName === 'IFRAME') {
              try {
                if (element.contentDocument) scan(element.contentDocument);
              } catch (_error) {
                // Cross-origin frames are intentionally inaccessible.
              }
            }
          }
        };
        scan(document);
        return result;
        """
    )
    if result["injectedImage"] or result["executionMarker"]:
        raise RuntimeError(f"portal executed identity-derived HTML: {result!r}")
    hostile_display_name = "<img src=x onerror=document.body.dataset.nasXss=1>"
    if require_hostile_display_name:
        identity = fetch_request(driver, "/identity/api/v3/core/users/me/", "GET")
        try:
            identity_body = json.loads(str(identity.get("body", "")))
        except json.JSONDecodeError as error:
            raise RuntimeError(f"current-user identity response was not JSON: {identity!r}") from error
        if int(identity.get("status", 0)) != 200 or identity_body.get("user", {}).get("name") != hostile_display_name:
            raise RuntimeError(f"current-user identity did not contain the hostile display name: {identity!r}")


def run_account(
    origin: str,
    username: str,
    password: str,
    expectations: list[RouteExpectation],
    settings: bool,
    personal_files: bool = False,
) -> None:
    driver = browser()
    try:
        browser_step(driver, f"Portal login ({username})", lambda: login(driver, origin, username, password))
        browser_step(
            driver,
            f"Portal rendering and console ({username})",
            lambda: verify_rendering_quality(driver, f"portal for {username}"),
        )
        browser_step(
            driver, f"Portal identity text ({username})", lambda: verify_no_identity_markup_injection(driver, username)
        )
        browser_step(driver, f"Portal capability routes ({username})", lambda: verify_routes(driver, expectations))
        browser_step(
            driver, f"Portal native share route ({username})", lambda: verify_native_share_route(driver, origin)
        )
        if personal_files:
            browser_step(
                driver,
                f"Personal file operations ({username})",
                lambda: verify_personal_file_operations(driver, username),
            )
        if settings:
            browser_step(driver, f"Portal settings form ({username})", lambda: verify_settings_form(driver, origin))
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


def capability_routes(ai_enabled: bool) -> dict[str, str]:
    routes = {
        "files": "/shares/",
        "webdav": "/dav/",
        "vault": "/vault/",
        "syncthing": "/settings/syncthing",
    }
    if ai_enabled:
        routes["ai"] = "/ai/"
    return routes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="https://nas-test.local")
    parser.add_argument("--administrator-password-file")
    parser.add_argument("--operator-password-file")
    parser.add_argument("--alice-password-file")
    parser.add_argument("--baseline-password-file")
    parser.add_argument("--post-a-password-file")
    parser.add_argument("--post-b-password-file")
    parser.add_argument("--bootstrap-password-file")
    parser.add_argument("--bootstrap-only", action="store_true")
    parser.add_argument("--identity-xss-only", action="store_true")
    parser.add_argument("--syncthing-admin-only", action="store_true")
    parser.add_argument("--ai-enabled", action="store_true")
    args = parser.parse_args()
    if args.bootstrap_only:
        if args.bootstrap_password_file is None:
            parser.error("--bootstrap-only requires --bootstrap-password-file")
        password = read_secret(args.bootstrap_password_file)
        verify_callback_return_paths(args.origin, "akadmin", password, ["/setup", "/console/"])
        verify_launcher_opens_console(args.origin, "akadmin", password)
        run_account(
            args.origin,
            "akadmin",
            password,
            [
                RouteExpectation("/", True, "/identity/if/user/"),
                RouteExpectation("/setup", True),
                RouteExpectation("/console/", True),
            ],
            False,
        )
        print("bootstrap administrator browser authorization checks ok")
        return 0
    if args.identity_xss_only:
        if args.alice_password_file is None:
            parser.error("--identity-xss-only requires --alice-password-file")
        password = read_secret(args.alice_password_file)
        driver = browser()
        try:
            login(driver, args.origin, "alice", password)
            verify_no_identity_markup_injection(driver, "alice", require_hostile_display_name=True)
        finally:
            driver.quit()
        print("hostile identity display name remained inert")
        return 0
    if args.syncthing_admin_only:
        if args.administrator_password_file is None:
            parser.error("--syncthing-admin-only requires --administrator-password-file")
        password = read_secret(args.administrator_password_file)
        driver = browser()
        try:
            login(driver, args.origin, "nasadmin", password)
            verify_routes(driver, [RouteExpectation("/syncthing/", True)])
            verify_administrator_syncthing_folders(driver, ["post-a", "post-b"])
        finally:
            driver.quit()
        print("administrator Syncthing folder visibility checks ok")
        return 0
    required_password_files = {
        "--administrator-password-file": args.administrator_password_file,
        "--operator-password-file": args.operator_password_file,
        "--alice-password-file": args.alice_password_file,
        "--baseline-password-file": args.baseline_password_file,
        "--post-a-password-file": args.post_a_password_file,
        "--post-b-password-file": args.post_b_password_file,
    }
    missing_password_files = [name for name, path in required_password_files.items() if path is None]
    if missing_password_files:
        parser.error("missing required arguments: " + ", ".join(missing_password_files))
    assert args.administrator_password_file is not None
    assert args.operator_password_file is not None
    assert args.alice_password_file is not None
    assert args.baseline_password_file is not None
    assert args.post_a_password_file is not None
    assert args.post_b_password_file is not None
    administrator_password = read_secret(args.administrator_password_file)
    operator_password = read_secret(args.operator_password_file)
    alice_password = read_secret(args.alice_password_file)
    baseline_password = read_secret(args.baseline_password_file)
    post_a_password = read_secret(args.post_a_password_file)
    post_b_password = read_secret(args.post_b_password_file)
    verify_cockpit_react_interactions(args.origin, "nasadmin", administrator_password)
    assign_application_capabilities(
        args.origin,
        "nasadmin",
        administrator_password,
        "alice",
        [
            "application.copyparty.files",
            "application.syncthing.access",
            "application.vaultwarden.access",
        ],
    )
    routes = capability_routes(args.ai_enabled)
    common_allowed = [
        RouteExpectation(routes["files"], True),
        RouteExpectation(routes["vault"], True),
    ]
    operator_expectations = common_allowed + [
        RouteExpectation(routes["webdav"], True),
        RouteExpectation(routes["syncthing"], True, "/identity/if/flow/nas-user-settings/"),
        RouteExpectation("/syncthing/", True),
        RouteExpectation("/alerts/", True),
        RouteExpectation("/victoriametrics/", True),
        RouteExpectation("/console/", True),
        RouteExpectation("/shares/admin/", True),
        RouteExpectation("/vault/admin/", True),
    ]
    if args.ai_enabled:
        operator_expectations.append(RouteExpectation(routes["ai"], True))
    run_account(
        args.origin,
        "operator",
        operator_password,
        operator_expectations,
        True,
    )
    alice_expectations = common_allowed + [
        RouteExpectation(routes["webdav"], False),
        RouteExpectation(routes["syncthing"], True, "/identity/if/flow/nas-user-settings/"),
        RouteExpectation("/syncthing/", False),
        RouteExpectation("/alerts/", False),
        RouteExpectation("/victoriametrics/", False),
        RouteExpectation("/console/", False),
        RouteExpectation("/shares/admin/", False),
        RouteExpectation("/vault/admin/", False),
    ]
    if args.ai_enabled:
        alice_expectations.append(RouteExpectation(routes["ai"], False))
    run_account(
        args.origin,
        "alice",
        alice_password,
        alice_expectations,
        True,
        True,
    )
    run_account(
        args.origin,
        "baseline",
        baseline_password,
        [RouteExpectation(path, False) for path in routes.values()]
        + [
            RouteExpectation("/syncthing/", False),
            RouteExpectation("/console/", False),
            RouteExpectation("/shares/admin/", False),
            RouteExpectation("/vault/admin/", False),
        ],
        False,
    )
    denied_expectations = [RouteExpectation(path, False) for path in routes.values()] + [
        RouteExpectation("/syncthing/", False),
        RouteExpectation("/console/", False),
        RouteExpectation("/shares/admin/", False),
        RouteExpectation("/vault/admin/", False),
    ]
    assign_application_capabilities(args.origin, "nasadmin", administrator_password, "post-a", [])
    assign_application_capabilities(args.origin, "nasadmin", administrator_password, "post-b", [])
    run_account(args.origin, "post-a", post_a_password, denied_expectations, False)
    run_account(args.origin, "post-b", post_b_password, denied_expectations, False)
    assign_application_capabilities(
        args.origin,
        "nasadmin",
        administrator_password,
        "post-a",
        ["application.copyparty.files", "application.syncthing.access"],
    )
    assign_application_capabilities(
        args.origin,
        "nasadmin",
        administrator_password,
        "post-b",
        ["application.copyparty.files", "application.syncthing.access"],
    )
    post_a_expectations = [
        RouteExpectation(routes["files"], True),
        RouteExpectation(routes["syncthing"], True, "/identity/if/flow/nas-user-settings/"),
        RouteExpectation("/syncthing/", False),
        RouteExpectation("/console/", False),
        RouteExpectation("/shares/admin/", False),
        RouteExpectation("/vault/admin/", False),
    ] + [RouteExpectation(path, False) for name, path in routes.items() if name not in {"files", "syncthing"}]
    run_account(args.origin, "post-a", post_a_password, post_a_expectations, True)
    run_account(
        args.origin,
        "post-b",
        post_b_password,
        [
            RouteExpectation(routes["files"], True),
            RouteExpectation(routes["syncthing"], True, "/identity/if/flow/nas-user-settings/"),
        ]
        + [RouteExpectation(path, False) for name, path in routes.items() if name not in {"files", "syncthing"}]
        + [
            RouteExpectation("/syncthing/", False),
            RouteExpectation("/console/", False),
            RouteExpectation("/shares/admin/", False),
            RouteExpectation("/vault/admin/", False),
        ],
        False,
    )
    assign_application_capabilities(args.origin, "nasadmin", administrator_password, "post-b", [])
    run_account(args.origin, "post-b", post_b_password, denied_expectations, False)
    assign_application_capabilities(
        args.origin,
        "nasadmin",
        administrator_password,
        "post-b",
        ["application.copyparty.files", "application.syncthing.access"],
    )
    verify_copy_party_user_isolation(
        args.origin,
        ("nasadmin", administrator_password),
        [("post-a", post_a_password), ("post-b", post_b_password)],
    )
    print("browser authorization, rendering, layout, and console checks ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
