#!/usr/bin/env python3
"""Complete appliance first start through the GUI bootstrap system.

Drives the Cockpit First start page (behind the Authentik gate) exactly as an
operator would: sign in with the documented bootstrap identity, review the
prepared plan, submit the KeePassXC password plus administrator details, and
wait for the submitted first-start job to finish. The resulting job document
is written to --result-file so the VM fixture can assert the full report.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import stat
import sys
import time
from typing import Any

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait


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


def first(driver: webdriver.Chrome, selectors: list[str]) -> Any:
    for selector in selectors:
        elements = driver.find_elements(By.CSS_SELECTOR, selector)
        for element in elements:
            if element.is_displayed() and element.is_enabled():
                return element
    return None


def browser_diagnostics(driver: webdriver.Chrome) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {"url": driver.current_url, "title": driver.title}
    try:
        pre = driver.find_element(By.CSS_SELECTOR, "pre.nas-pre")
        diagnostics["jobOutput"] = pre.text[-4000:]
    except WebDriverException:
        pass
    try:
        body = driver.find_element(By.TAG_NAME, "body")
        diagnostics["body"] = body.text[-2000:]
    except WebDriverException:
        pass
    try:
        diagnostics["console"] = [
            {"level": entry.get("level"), "message": entry.get("message")[-500:]}
            for entry in driver.get_log("browser")[-20:]
        ]
    except (WebDriverException, ValueError):
        pass
    return diagnostics


def login(driver: webdriver.Chrome, origin: str, username: str, password: str) -> None:
    driver.get(origin.rstrip("/") + "/")
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
    public_origin = origin.rstrip("/")

    def authenticated(current: webdriver.Chrome) -> bool:
        url = current.current_url
        if "/identity/" in url or "/outpost.goauthentik.io/callback" in url:
            return False
        return url == public_origin or url.startswith(public_origin + "/")

    try:
        wait.until(authenticated)
    except TimeoutException as error:
        details = json.dumps(browser_diagnostics(driver), indent=2, sort_keys=True)
        raise RuntimeError(f"Authentik browser login did not complete for {username!r}:\n{details}") from error


def open_setup_page(driver: webdriver.Chrome, origin: str) -> WebDriverWait:
    driver.get(origin.rstrip("/") + "/console/cockpit/@localhost/nas/index.html#/setup")
    wait = WebDriverWait(driver, 60)
    wait.until(lambda current: first(current, ["#first-start-keepass-password"]))
    return wait


def fill_wizard(
    driver: webdriver.Chrome,
    wait: WebDriverWait,
    args: argparse.Namespace,
    kee_pass_password: str,
    admin_password: str,
) -> None:
    def send(selector: str, value: str) -> None:
        element = wait.until(lambda current: first(current, [selector]))
        element.clear()
        element.send_keys(value)

    send("#first-start-keepass-password", kee_pass_password)
    send("#first-start-administrator-username", args.admin_username)
    send("#first-start-administrator-name", args.admin_name)
    send("#first-start-administrator-email", args.admin_email)
    send("#first-start-administrator-password", admin_password)

    for device in args.device:
        checkbox = wait.until(lambda current: first(current, [f'input[id="first-start-device-{device}"]']))
        if not checkbox.is_selected():
            checkbox.click()

    destructive = first(driver, ["#first-start-destructive"])
    if destructive is not None and not destructive.is_selected():
        destructive.click()

    start_button = wait.until(
        lambda current: next(
            (
                element
                for element in current.find_elements(By.CSS_SELECTOR, "button")
                if element.is_displayed() and element.is_enabled() and element.text.strip() == "Start"
            ),
            None,
        ),
    )
    start_button.click()


def wait_for_job(driver: webdriver.Chrome, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_text = ""
    while time.monotonic() < deadline:
        try:
            pre = driver.find_element(By.CSS_SELECTOR, "pre.nas-pre")
            last_text = pre.text
            job = json.loads(last_text)
        except (WebDriverException, json.JSONDecodeError):
            time.sleep(2)
            continue
        status = job.get("status")
        if status in {"complete", "failed"}:
            return job
        time.sleep(2)
    details = json.dumps(browser_diagnostics(driver), indent=2, sort_keys=True)
    raise RuntimeError(
        f"first-start job did not finish within {timeout_seconds}s; last output: {last_text[-2000:]}\n{details}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, help="Public NAS origin, e.g. https://nas-test.local:8443")
    parser.add_argument("--bootstrap-password-file", required=True, help="File with the Authentik bootstrap password")
    parser.add_argument("--keepass-password-file", required=True, help="File with the KeePassXC database password")
    parser.add_argument("--admin-username", required=True)
    parser.add_argument("--admin-name", required=True)
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password-file", required=True, help="File with the administrator password")
    parser.add_argument("--device", action="append", default=[], help="Storage device to confirm; repeatable")
    parser.add_argument("--job-timeout-seconds", type=int, default=1200)
    parser.add_argument("--result-file", help="Write the final job document JSON here")
    args = parser.parse_args()

    bootstrap_password = read_secret(args.bootstrap_password_file)
    keepass_password = read_secret(args.keepass_password_file)
    admin_password = read_secret(args.admin_password_file)
    ssl._create_default_https_context = ssl._create_unverified_context

    driver = browser()
    try:
        login(driver, args.origin, "akadmin", bootstrap_password)
        wait = open_setup_page(driver, args.origin)
        fill_wizard(driver, wait, args, keepass_password, admin_password)
        job = wait_for_job(driver, args.job_timeout_seconds)
    except Exception:
        try:
            print(json.dumps(browser_diagnostics(driver), indent=2, sort_keys=True), file=sys.stderr)
        finally:
            driver.quit()
        raise
    finally:
        try:
            driver.quit()
        except WebDriverException:
            pass

    if job.get("status") != "complete":
        raise RuntimeError(f"first-start job failed: {json.dumps(job, indent=2, sort_keys=True)}")
    if args.result_file:
        with open(args.result_file, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(job, indent=2, sort_keys=True) + "\n")
    print("first-run wizard job completed:", job.get("jobId"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
