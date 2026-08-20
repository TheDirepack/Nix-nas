#!/usr/bin/env python3
"""Deterministic browser probes against the built Cockpit bundle.

Runs inside the installed VM guest where the packaged Chromium, chromedriver,
and Selenium are available. It serves ``cockpit/dist`` over loopback with a
stub ``base1/cockpit.js`` (so the React app mounts outside the real Cockpit
shell), injects a cockpit API mock shaped like the Managed Services V2 data
model, and asserts that hostile backend strings render inert, the layout stays
inside the viewport across common sizes and text scales, DOM ids are unique,
interactive controls do not overlap, and scriptable navigation schemes never
appear in rendered links.

This is the deterministic bundle layer. The real-appliance browser layer lives
in ``tests/browser/authz.py`` and runs against the installed Cockpit/Caddy
stack after authentication.
"""

from __future__ import annotations

import argparse
import http.server
import json
import shutil
import socketserver
import tempfile
import threading
from pathlib import Path
from typing import Any, cast

from selenium.common.exceptions import WebDriverException
from selenium.webdriver.support.ui import WebDriverWait

from authz import browser, rendered_text

HOST = "127.0.0.1"
PORT = 4173
VIEWPORTS = ((320, 720), (768, 900), (1280, 900), (1920, 1080))
TEXT_SCALES = (1.0, 2.0)
LAYOUT_LIMIT = 80

XSS_PAYLOADS = (
    ("script-tag", "<script>globalThis.__nas_xss=1</script>"),
    ("img-onerror", '<img src=x onerror="globalThis.__nas_xss=2">'),
    ("svg-onload", "<svg/onload=globalThis.__nas_xss=3>"),
    ("details-ontoggle", "<details open ontoggle=globalThis.__nas_xss=4>x</details>"),
    ("iframe-srcdoc", '<iframe srcdoc="<script>parent.__nas_xss=5<\\/script>"></iframe>'),
    ("javascript-url", "javascript:globalThis.__nas_xss=6"),
    ("data-html-url", "data:text/html,<script>parent.__nas_xss=7</script>"),
    ("attribute-breakout", '"><img src=x onerror=globalThis.__nas_xss=8>'),
    ("single-quote-breakout", "'><svg onload=globalThis.__nas_xss=9>"),
    ("encoded-script", "&lt;script&gt;globalThis.__nas_xss=10&lt;/script&gt;"),
    ("mixed-case", "<ScRiPt>globalThis.__nas_xss=11</ScRiPt>"),
    ("nullish-tag", "<img src=x onerror=globalThis.__nas_xss=12\u0000>"),
    ("css-url", 'url("javascript:globalThis.__nas_xss=13")'),
    ("event-newline", '<img src=x\nonerror="globalThis.__nas_xss=14">'),
)

MOCK_TEMPLATE = """
globalThis.__nas_xss = 0;
(() => {
  const data = %(payload)s;
  const spawn = () => {
    const promise = Promise.resolve(JSON.stringify(data));
    promise.input = () => {};
    promise.stream = () => promise;
    return promise;
  };
  globalThis.cockpit = {spawn};
})();
"""


def mock_data(value: str) -> dict[str, Any]:
    """Overview payload matching the fields the V2 React app consumes."""
    return {
        "host": value,
        "protectedReady": True,
        "setup": {
            "firstStart": {"status": "complete", "message": value},
            "setupState": {"status": "complete"},
        },
        "managedServices": {
            "services": [
                {
                    "id": "ai-runtime",
                    "label": value,
                    "description": value,
                    "requestedMode": "on-demand",
                    "effectiveMode": "on-demand",
                    "allowedModes": ["off", "on-demand", "always"],
                    "managed": True,
                    "running": True,
                    "healthy": True,
                    "idleSeconds": 300,
                    "units": [{"unit": "nas-llama-swap.service", "active": True, "memoryBytes": 1048576}],
                },
            ],
        },
        "managedServiceLinks": [
            {"id": "grafana", "label": value, "url": "/grafana/", "category": "Observability", "order": 0},
        ],
        "links": {
            "identity": value,
            "docs": "/docs/",
            "files": "/files/",
            "storage": "/storage/",
        },
        "update": {
            "ok": True,
            "revision": value,
            "branch": "main",
            "upstream": "origin/main",
            "ahead": 0,
            "behind": 0,
            "dirty": False,
        },
        "operations": {"busyClasses": [], "conflictsByAction": {}, "managedServicesConflicts": []},
        "zfs": {"ok": True, "healthy": True, "summary": value, "dataset": "tank/nas"},
        "failedUnits": [value],
        "backupRemote": {"provider": "local", "scope": "config-only", "rcloneRemote": value},
        "zfsReplicationInstalled": True,
    }


class BundleHandler(http.server.BaseHTTPRequestHandler):
    """Serve a copied dist tree plus a generated base1/cockpit.js mock."""

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        server = cast(ReusableServer, self.server)
        if self.path.split("?", 1)[0] == "/base1/cockpit.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(
                (MOCK_TEMPLATE % {"payload": json.dumps(server.mock_data, ensure_ascii=True)}).encode("utf-8")
            )
            return
        candidate = server.dist_root / self.path.lstrip("/")
        try:
            candidate = candidate.resolve()
            candidate.relative_to(server.dist_root.resolve())
        except ValueError:
            self.send_error(403)
            return
        if candidate.is_dir():
            candidate = candidate / "index.html"
        if not candidate.is_file():
            self.send_error(404)
            return
        content = candidate.read_bytes()
        suffix = candidate.suffix.lower()
        content_type = {
            ".js": "application/javascript",
            ".css": "text/css",
            ".html": "text/html",
            ".json": "application/json",
            ".woff2": "font/woff2",
            ".svg": "image/svg+xml",
        }.get(suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


class ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    dist_root: Path
    mock_data: dict[str, Any]


def layout_metrics(driver: Any) -> dict[str, Any]:
    return driver.execute_script(
        """
        const viewport = document.documentElement.clientWidth;
        const visible = element => {
          const style = getComputedStyle(element);
          const rect = element.getBoundingClientRect();
          return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
        };
        const controls = Array.from(document.querySelectorAll(
          'a[href],button,input,select,textarea,[role="button"],[role="link"],[tabindex]:not([tabindex="-1"])'
        )).filter(visible).slice(0, %(limit)d).map(element => {
          const rect = element.getBoundingClientRect();
          return {
            tag: element.tagName,
            text: (element.innerText || element.getAttribute('aria-label') || '').trim().slice(0, 80),
            x: rect.x,
            y: rect.y,
            width: rect.width,
            height: rect.height,
          };
        });
        const overflow = controls.filter(box => box.x < -1 || box.x + box.width > viewport + 1);
        const ids = Array.from(document.querySelectorAll('[id]')).map(element => element.id).filter(Boolean);
        const duplicates = [...new Set(ids.filter((value, index) => ids.indexOf(value) !== index))];
        const collisions = [];
        for (let left = 0; left < controls.length; left += 1) {
          for (let right = left + 1; right < controls.length; right += 1) {
            const a = controls[left];
            const b = controls[right];
            const overlapWidth = Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x);
            const overlapHeight = Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y);
            if (overlapWidth > 4 && overlapHeight > 4) {
              collisions.push({a: a.text, b: b.text, overlapWidth, overlapHeight});
            }
          }
        }
        const hrefs = Array.from(document.querySelectorAll('a[href]')).map(node => node.getAttribute('href') || '');
        const scriptable = hrefs.filter(href => /^\\s*(javascript|data:text\\/html|vbscript):/i.test(href.trim()));
        return {
          viewport,
          documentWidth: document.documentElement.scrollWidth,
          bodyWidth: document.body ? document.body.scrollWidth : 0,
          overflow,
          duplicates,
          collisions: collisions.slice(0, 8),
          scriptable,
        };
        """
        % {"limit": LAYOUT_LIMIT},
    )


def expected_console_noise(entry: dict[str, Any]) -> bool:
    """Ignore the automatic favicon request, which the bundle never provides."""
    return "/favicon.ico" in str(entry.get("message", ""))


def severe_console_entries(driver: Any) -> list[dict[str, Any]]:
    try:
        return [
            entry
            for entry in driver.get_log("browser")
            if entry.get("level") == "SEVERE" and not expected_console_noise(entry)
        ]
    except (WebDriverException, ValueError):
        return []


def verify_layout(driver: Any) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for width, height in VIEWPORTS:
        driver.set_window_size(width, height)
        for scale in TEXT_SCALES:
            driver.execute_script(f"document.documentElement.style.fontSize = '{int(scale * 100)}%'")
            WebDriverWait(driver, 20).until(
                lambda current: current.execute_script("return document.readyState") in {"interactive", "complete"}
            )
            metrics = layout_metrics(driver)
            if metrics["documentWidth"] > metrics["viewport"] + 1 or metrics["bodyWidth"] > metrics["viewport"] + 1:
                failures.append(
                    {"viewport": [width, height], "scale": scale, "reason": "horizontal-overflow", **metrics}
                )
            if metrics["overflow"]:
                failures.append({"viewport": [width, height], "scale": scale, "reason": "control-overflow", **metrics})
            if metrics["duplicates"]:
                failures.append({"viewport": [width, height], "scale": scale, "reason": "duplicate-dom-ids", **metrics})
            if metrics["collisions"]:
                failures.append({"viewport": [width, height], "scale": scale, "reason": "control-collision", **metrics})
            if metrics["scriptable"]:
                failures.append({"viewport": [width, height], "scale": scale, "reason": "scriptable-link", **metrics})
    severe = severe_console_entries(driver)
    if severe:
        failures.append({"reason": "browser-console-errors", "entries": severe[-20:]})
    return failures


def verify_xss_probe(driver: Any, payload: str) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    driver.refresh()
    WebDriverWait(driver, 20).until(lambda current: "NixOS NAS" in current.page_source)
    state = driver.execute_script(
        """
        return {
          marker: window.__nas_xss,
          executable: Array.from(document.querySelectorAll('script,iframe,svg,img'))
            .map(node => node.outerHTML)
            .filter(markup => markup.includes('__nas_xss')),
        };
        """
    )
    if state["marker"] != 0:
        failures.append({"reason": "xss-executed", "marker": state["marker"]})
    if state["executable"]:
        failures.append({"reason": "executable-markup", "markup": state["executable"][:4]})
    if payload.replace("\u0000", "") not in rendered_text(driver).replace("\u0000", ""):
        failures.append({"reason": "payload-not-inert-text"})
    severe = severe_console_entries(driver)
    if severe:
        failures.append({"reason": "browser-console-errors", "entries": severe[-20:]})
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--evidence", default="", type=Path)
    parser.add_argument("--port", default=PORT, type=int)
    args = parser.parse_args()
    dist = args.dist.resolve()
    if not (dist / "index.html").is_file():
        raise SystemExit(f"Cockpit distribution is missing index.html: {dist}")
    if not (dist / "index.js").is_file():
        raise SystemExit(f"Cockpit distribution is missing index.js: {dist}")

    driver = browser()
    evidence: dict[str, Any] = {"ok": False}
    try:
        with tempfile.TemporaryDirectory(prefix="nas-deterministic-bundle-") as work:
            dist_root = Path(work) / "dist"
            shutil.copytree(dist, dist_root)
            server = ReusableServer(
                (HOST, args.port),
                BundleHandler,
            )
            server.dist_root = dist_root
            server.mock_data = mock_data("NAS host")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                try:
                    origin = f"http://{HOST}:{args.port}"
                    driver.get(origin + "/index.html")
                    WebDriverWait(driver, 30).until(lambda current: "NixOS NAS" in current.page_source)
                except WebDriverException as exc:
                    raise SystemExit(f"deterministic bundle did not mount: {exc}") from exc

                layout_failures: list[dict[str, Any]] = []
                try:
                    layout_failures = verify_layout(driver)
                except WebDriverException as exc:
                    layout_failures.append({"reason": "layout-driver-exception", "error": str(exc)})

                xss_failures: list[dict[str, Any]] = []
                for name, payload in XSS_PAYLOADS:
                    server.mock_data = mock_data(payload)
                    try:
                        probe_failures = verify_xss_probe(driver, payload)
                    except WebDriverException as exc:
                        probe_failures = [{"reason": "probe-driver-exception", "error": str(exc)}]
                    for failure in probe_failures:
                        xss_failures.append({"payload": name, **failure})
            finally:
                server.shutdown()
                thread.join(timeout=5)
    finally:
        driver.quit()

    evidence = {
        "ok": not layout_failures and not xss_failures,
        "engine": "selenium",
        "probes": len(XSS_PAYLOADS),
        "layoutFailures": layout_failures[:10],
        "xssFailures": xss_failures[:10],
    }
    if args.evidence:
        evidence_path = args.evidence.resolve()
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not evidence["ok"]:
        raise SystemExit(json.dumps(evidence, indent=2, sort_keys=True))
    print(f"deterministic bundle XSS and layout probes ok ({evidence['probes']} hostile inputs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
