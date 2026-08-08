#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-unauthenticated}"
TARGET="${2:-${NAS_ZAP_TARGET:-}}"
OUT_DIR="${NAS_ZAP_OUT_DIR:-$PWD/zap-report}"
IMAGE="${NAS_ZAP_IMAGE:-}"
RUNTIME="${NAS_CONTAINER_RUNTIME:-}"
DURATION="${NAS_ZAP_AUTOMATION_MINUTES:-90}"
BROWSERS="${NAS_ZAP_BROWSER_WORKERS:-2}"
USER_NAME="${NAS_ZAP_AUTH_USER:-}"
USER_PASSWORD="${NAS_ZAP_AUTH_PASSWORD:-}"

usage() {
  cat <<'USAGE'
Usage: scripts/zap-automation-scan.sh [unauthenticated|authenticated] <target-url>

Run OWASP ZAP's Automation Framework against an explicitly disposable target.
The plan uses the modern Client Spider to discover live DOM/application state,
then feeds the discovered attack surface into ZAP's passive and active scanners.
Authenticated mode uses ZAP browser-based authentication and session auto-detection.

Required:
  NAS_ZAP_IMAGE              ZAP image pinned by immutable sha256 digest
  NAS_ZAP_AUTH_USER          required in authenticated mode
  NAS_ZAP_AUTH_PASSWORD      required in authenticated mode

Optional:
  NAS_CONTAINER_RUNTIME      docker or podman (auto-detected)
  NAS_ZAP_OUT_DIR            report directory
  NAS_ZAP_AUTOMATION_MINUTES active-scan/client-spider budget, 1..240 (default 90)
  NAS_ZAP_BROWSER_WORKERS    parallel Client Spider browsers, 1..4 (default 2)
  NAS_ZAP_ALLOW_PUBLIC_TARGET=1
                              permit non-local/private targets; never use casually

The scanner actively attacks the target. It is intended for the disposable NAS
VM harness only unless you explicitly own and authorize another target.
USAGE
}

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

case "$MODE" in
  unauthenticated|authenticated) ;;
  -h|--help|help) usage; exit 0 ;;
  *) usage >&2; die "unknown scan mode: $MODE" ;;
esac
[[ -n "$TARGET" ]] || die "target URL is required"
[[ "$TARGET" =~ ^https?:// ]] || die "target must use http:// or https://"
[[ "$IMAGE" =~ @sha256:[0-9a-fA-F]{64}$ ]] || die "NAS_ZAP_IMAGE must be pinned to an immutable sha256 digest"
[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || die "NAS_ZAP_AUTOMATION_MINUTES must be a positive integer"
(( DURATION <= 240 )) || die "NAS_ZAP_AUTOMATION_MINUTES must not exceed 240"
[[ "$BROWSERS" =~ ^[1-4]$ ]] || die "NAS_ZAP_BROWSER_WORKERS must be between 1 and 4"
if [[ "$MODE" == authenticated ]]; then
  [[ -n "$USER_NAME" && -n "$USER_PASSWORD" ]] || die "authenticated mode requires NAS_ZAP_AUTH_USER and NAS_ZAP_AUTH_PASSWORD"
fi

if [[ "${NAS_ZAP_ALLOW_PUBLIC_TARGET:-0}" != 1 ]]; then
  python3 - "$TARGET" <<'PY_TARGET' || die "target is not local/private"
import ipaddress
import sys
from urllib.parse import urlsplit

host = (urlsplit(sys.argv[1]).hostname or "").rstrip(".").lower()
if host == "localhost" or host.endswith(".local"):
    raise SystemExit(0)
try:
    address = ipaddress.ip_address(host)
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if (address.is_private or address.is_loopback or address.is_link_local) else 1)
PY_TARGET
fi

if [[ -z "$RUNTIME" ]]; then
  if command -v docker >/dev/null 2>&1; then
    RUNTIME=docker
  elif command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
  else
    die "docker or podman is required"
  fi
fi
case "$RUNTIME" in docker|podman) ;; *) die "NAS_CONTAINER_RUNTIME must be docker or podman" ;; esac
command -v "$RUNTIME" >/dev/null 2>&1 || die "$RUNTIME is not installed"

install -d -m 0755 "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"
plan="$OUT_DIR/zap-automation-$MODE.yaml"
report_prefix="zap-automation-$MODE"

# JSON is valid YAML and lets the stdlib encoder handle credentials/URLs safely.
python3 - "$MODE" "$TARGET" "$DURATION" "$BROWSERS" "$USER_NAME" "$USER_PASSWORD" "$plan" "$report_prefix" <<'PY_PLAN'
from __future__ import annotations

import json
import sys

mode, target, duration_text, browsers_text, username, password, output, prefix = sys.argv[1:]
duration = int(duration_text)
browsers = int(browsers_text)
context = {
    "name": "nas-target",
    "urls": [target],
}
user_name = None
if mode == "authenticated":
    user_name = "nas-browser-user"
    context.update(
        {
            "authentication": {
                "method": "browser",
                "parameters": {
                    "loginPageUrl": target,
                    "loginPageWait": 5,
                    "browserId": "firefox-headless",
                    "diagnostics": True,
                },
                "verification": {"method": "autodetect"},
            },
            "sessionManagement": {"method": "autodetect", "parameters": {}},
            "users": [
                {
                    "name": user_name,
                    "credentials": {"username": username, "password": password},
                }
            ],
        }
    )

spider_parameters = {
    "context": "nas-target",
    "url": target,
    "browserId": "firefox-headless",
    "numberOfBrowsers": browsers,
    "maxDuration": duration,
    "maxCrawlDepth": 12,
    "maxChildren": 100,
}
active_parameters = {"context": "nas-target", "url": target}
if user_name:
    spider_parameters["user"] = user_name
    active_parameters["user"] = user_name

plan = {
    "env": {
        "contexts": [context],
        "parameters": {
            "failOnError": True,
            "failOnWarning": False,
            "progressToStdout": True,
        },
    },
    "jobs": [
        {"type": "spiderClient", "parameters": spider_parameters},
        {"type": "passiveScan-wait"},
        {
            "type": "activeScan-config",
            "parameters": {
                "maxRuleDurationInMins": min(20, duration),
                "maxScanDurationInMins": duration,
                "handleAntiCSRFTokens": True,
            },
        },
        {"type": "activeScan", "parameters": active_parameters},
        {"type": "passiveScan-wait"},
        {
            "type": "report",
            "parameters": {
                "template": "modern",
                "reportDir": "/zap/wrk",
                "reportFile": f"{prefix}.html",
                "reportTitle": f"NixOS NAS ZAP {mode} scan",
                "displayReport": False,
            },
        },
        {
            "type": "report",
            "parameters": {
                "template": "traditional-json",
                "reportDir": "/zap/wrk",
                "reportFile": f"{prefix}.json",
                "reportTitle": f"NixOS NAS ZAP {mode} scan",
                "displayReport": False,
            },
        },
        {
            "type": "exitStatus",
            "parameters": {
                "errorLevel": "Medium",
                "warnLevel": "Low",
                "okExitValue": 0,
                "warnExitValue": 2,
                "errorExitValue": 1,
            },
            "alwaysRun": True,
        },
    ],
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(plan, handle, indent=2)
    handle.write("\n")
PY_PLAN
chmod 0600 "$plan"

runtime_args=(run --rm --network host -v "$OUT_DIR:/zap/wrk:rw")
# Pass credentials only as process environment for variable-safe plan generation;
# they are already materialized in the root/runner-readable temporary plan.
process_timeout="${NAS_ZAP_AUTOMATION_TIMEOUT_SECONDS:-$((DURATION * 60 + 600))}"
[[ "$process_timeout" =~ ^[1-9][0-9]*$ ]] || die "NAS_ZAP_AUTOMATION_TIMEOUT_SECONDS must be a positive integer"
(( process_timeout <= 18000 )) || die "NAS_ZAP_AUTOMATION_TIMEOUT_SECONDS must not exceed 18000"

printf 'Running state-aware ZAP %s scan against %s (%s minute budget, %s browser workers)\n' \
  "$MODE" "$TARGET" "$DURATION" "$BROWSERS"
set +e
timeout --signal=TERM --kill-after=60s "${process_timeout}s" \
  "$RUNTIME" "${runtime_args[@]}" "$IMAGE" \
  zap.sh -cmd -autorun "/zap/wrk/$(basename "$plan")"
rc=$?
set -e
rm -f "$plan"
if [[ "$rc" == 124 || "$rc" == 137 ]]; then
  die "ZAP automation scan exceeded its ${process_timeout}s process deadline"
fi
(( rc == 0 )) || die "ZAP automation $MODE scan failed with exit code $rc"

for report in "$OUT_DIR/$report_prefix.html" "$OUT_DIR/$report_prefix.json"; do
  [[ -s "$report" ]] || die "ZAP automation did not produce expected report: $report"
done
printf 'ZAP automation %s scan completed: %s\n' "$MODE" "$OUT_DIR"
