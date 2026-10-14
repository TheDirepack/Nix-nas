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
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'USAGE'
Usage: scripts/zap-automation-scan.sh [unauthenticated|authenticated] <target-url>

Run OWASP ZAP's Automation Framework against an explicitly disposable target.
The plan uses the modern Client Spider to discover live DOM/application state,
then feeds the discovered attack surface into ZAP's passive and active scanners.
Authenticated mode uses browser authentication and verifies the Authentik session.

Required:
  NAS_ZAP_IMAGE              ZAP image pinned by immutable sha256 digest
  NAS_ZAP_CONFIRM_ACTIVE=1   confirm authorization for the active scan
  NAS_ZAP_AUTH_USER          required in authenticated mode
  NAS_ZAP_AUTH_PASSWORD      required in authenticated mode

Optional:
  NAS_CONTAINER_RUNTIME      docker or podman (auto-detected)
  NAS_ZAP_OUT_DIR            report directory
  NAS_ZAP_AUTOMATION_MINUTES active-scan/client-spider budget, 1..240 (default 90)
  NAS_ZAP_BROWSER_WORKERS    parallel Client Spider browsers, 1..4 (default 2)
  NAS_ZAP_AUTH_VERIFY_PATH   same-origin user-session API path in authenticated
                            mode (default /identity/api/v3/core/users/me/)
  NAS_ZAP_ALLOW_PUBLIC_TARGET=1
                              permit non-local/private targets; never use casually

The scanner actively attacks the target. It is intended for the disposable NAS
VM harness only unless you explicitly own and authorize another target.
USAGE
}

die() { printf 'error: %s\n' "$*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

case "$MODE" in
  unauthenticated|authenticated) ;;
  -h|--help|help) usage; exit 0 ;;
  *) usage >&2; die "unknown scan mode: $MODE" ;;
esac
[[ "${NAS_ZAP_CONFIRM_ACTIVE:-0}" == 1 ]] || die "active scanning requires NAS_ZAP_CONFIRM_ACTIVE=1"
for cmd in python3 timeout id; do need "$cmd"; done
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
need "$RUNTIME"

install -d -m 0755 "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"
plan="$OUT_DIR/zap-automation-$MODE.yaml"
report_prefix="zap-automation-$MODE"

# JSON is valid YAML. Auth credentials stay as environment-variable references
# so the generated plan and uploaded reports never contain the plaintext secret.
python3 - "$MODE" "$TARGET" "$DURATION" "$BROWSERS" "$plan" "$report_prefix" <<'PY_PLAN'
from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urlsplit

mode, target, duration_text, browsers_text, output, prefix = sys.argv[1:]
duration = int(duration_text)
browsers = int(browsers_text)
parsed = urlsplit(target)
# Reports must include same-origin login redirects outside the starting path.
context = {
    "name": "nas-target",
    "urls": [target],
    "includePaths": [re.escape(f"{parsed.scheme}://{parsed.netloc}") + r"/.*"],
}
user_name = None
if mode == "authenticated":
    user_name = "nas-browser-user"
    verification_path = os.environ.get("NAS_ZAP_AUTH_VERIFY_PATH", "/identity/api/v3/core/users/me/")
    verification_url = urlsplit(verification_path)
    if not verification_path.startswith("/") or verification_path.startswith("//") or verification_url.netloc or verification_url.scheme:
        raise SystemExit("NAS_ZAP_AUTH_VERIFY_PATH must be a same-origin absolute path")
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
                "verification": {
                    "method": "poll",
                    "pollUrl": f"{parsed.scheme}://{parsed.netloc}{verification_path}",
                    "pollFrequency": 60,
                    "pollUnits": "requests",
                    "loggedInRegex": r'"username"\s*:\s*' + re.escape(json.dumps(os.environ["NAS_ZAP_AUTH_USER"])),
                },
            },
            "sessionManagement": {"method": "autodetect", "parameters": {}},
            "users": [
                {
                    "name": user_name,
                    "credentials": {
                        "username": "${NAS_ZAP_AUTH_USER}",
                        "password": "${NAS_ZAP_AUTH_PASSWORD}",
                    },
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
spider_job = {"type": "spiderClient", "parameters": spider_parameters}
discovery_jobs = [spider_job]
if user_name:
    spider_parameters["user"] = user_name
    active_parameters["user"] = user_name
    session_tests = [
        {
            "name": "authenticated session verified",
            "type": "stats",
            "statistic": "stats.auth.state.loggedin",
            "site": f"{parsed.scheme}://{parsed.netloc}",
            "operator": ">=",
            "value": 1,
            "onFail": "error",
        },
        {
            "name": "private identity response verified",
            "type": "url",
            "url": context["authentication"]["verification"]["pollUrl"],
            "operator": "or",
            "responseBodyRegex": context["authentication"]["verification"]["loggedInRegex"],
            "onFail": "error",
        },
    ]
    discovery_jobs.append({
        "type": "requestor",
        "parameters": {"user": user_name},
        "requests": [{"url": context["authentication"]["verification"]["pollUrl"], "responseCode": 200}],
        "tests": session_tests,
    })

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
        *discovery_jobs,
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
chmod 0644 "$plan"

# Match report bind-mount ownership; arbitrary UIDs need an existing Java home.
runtime_args=(run --rm --network host --user "$(id -u):$(id -g)"
  -e HOME=/tmp -e JAVA_TOOL_OPTIONS=-Duser.home=/tmp -v "$OUT_DIR:/zap/wrk:rw"
  -v "$SCRIPT_DIR/lib:/nas-zap:ro" --entrypoint bash -e NAS_ZAP_IMAGE
  -e "NAS_ZAP_ADDON_EVIDENCE=/zap/wrk/$report_prefix.addons.json")
if [[ -n "${NAS_ZAP_EXTRA_HOST:-}" ]]; then
  [[ "$NAS_ZAP_EXTRA_HOST" != *$'\n'* && "$NAS_ZAP_EXTRA_HOST" != *$'\r'* ]] || die "NAS_ZAP_EXTRA_HOST must be one line"
  runtime_args+=(--add-host "$NAS_ZAP_EXTRA_HOST")
fi
if [[ "$MODE" == authenticated ]]; then
  runtime_args+=(-e NAS_ZAP_AUTH_USER -e NAS_ZAP_AUTH_PASSWORD)
fi
process_timeout="${NAS_ZAP_AUTOMATION_TIMEOUT_SECONDS:-$((DURATION * 60 + 600))}"
[[ "$process_timeout" =~ ^[1-9][0-9]*$ ]] || die "NAS_ZAP_AUTOMATION_TIMEOUT_SECONDS must be a positive integer"
(( process_timeout <= 18000 )) || die "NAS_ZAP_AUTOMATION_TIMEOUT_SECONDS must not exceed 18000"

printf 'Running state-aware ZAP %s scan against %s (%s minute budget, %s browser workers)\n' \
  "$MODE" "$TARGET" "$DURATION" "$BROWSERS"
reports=("$OUT_DIR/$report_prefix.html" "$OUT_DIR/$report_prefix.json" "$OUT_DIR/$report_prefix.addons.json")
# Reused output directories must not supply evidence for an incomplete scan.
rm -f -- "${reports[@]}"
set +e
timeout --signal=TERM --kill-after=60s "${process_timeout}s" \
  "$RUNTIME" "${runtime_args[@]}" "$IMAGE" \
  /nas-zap/zap-entrypoint.sh zap.sh -cmd -config stats.inMemoryEnabled=true -autorun "/zap/wrk/$(basename "$plan")"
rc=$?
set -e
rm -f "$plan"
if [[ "$rc" == 124 || "$rc" == 137 ]]; then
  die "ZAP automation scan exceeded its ${process_timeout}s process deadline"
fi
(( rc == 0 )) || die "ZAP automation $MODE scan failed with exit code $rc"

for report in "${reports[@]}"; do
  [[ -s "$report" ]] || die "ZAP automation did not produce expected report: $report"
done
python3 "$SCRIPT_DIR/lib/zap-addons.py" verify-evidence --image "$IMAGE" \
  --evidence "$OUT_DIR/$report_prefix.addons.json" || die "invalid ZAP add-on evidence"
printf 'ZAP automation %s scan completed: %s\n' "$MODE" "$OUT_DIR"
