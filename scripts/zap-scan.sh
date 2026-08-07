#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-baseline}"
TARGET="${2:-${NAS_ZAP_TARGET:-}}"
OUT_DIR="${NAS_ZAP_OUT_DIR:-$PWD/zap-report}"
IMAGE="${NAS_ZAP_IMAGE:-}"
REPORT_PREFIX="${NAS_ZAP_REPORT_PREFIX:-scan}"
RUNTIME="${NAS_CONTAINER_RUNTIME:-}"

usage() {
  cat <<'USAGE'
Usage: scripts/zap-scan.sh [baseline|full] <target-url>

Run OWASP ZAP against an explicitly disposable/authorized target.

Required:
  NAS_ZAP_IMAGE   ZAP container image pinned by digest, for example
                  registry.example/zaproxy@sha256:<64 hex characters>

Optional:
  NAS_CONTAINER_RUNTIME  docker or podman (auto-detected when unset)
  NAS_ZAP_OUT_DIR        report directory (default: ./zap-report)
  NAS_ZAP_EXTRA_HOST     host mapping such as nas-test.local:127.0.0.1
  NAS_ZAP_MAX_MINUTES    scan duration passed to ZAP (default: 10 baseline, 30 full)
  NAS_ZAP_PROCESS_TIMEOUT_SECONDS
                         hard outer process deadline (default: scan duration + 120s)
  NAS_ZAP_REPORT_PREFIX  safe filename prefix for reports (default: scan)
  NAS_ZAP_ALLOW_PUBLIC_TARGET=1
                         allow a target outside localhost, .local, or private IP space
  NAS_ZAP_CONFIRM_ACTIVE=1
                         required for the full active scanner

Warnings and failures are fatal by default. The full scan actively attacks the
target and requires explicit confirmation; use it only against a disposable VM
or another system you own and have designated for security testing.
USAGE
}

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

case "$MODE" in
  baseline|full) ;;
  -h|--help|help) usage; exit 0 ;;
  *) usage >&2; die "unknown scan mode: $MODE" ;;
esac

[[ -n "$TARGET" ]] || die "target URL is required"
[[ "$TARGET" =~ ^https?:// ]] || die "target must use http:// or https://"
[[ "$IMAGE" =~ @sha256:[0-9a-fA-F]{64}$ ]] || \
  die "NAS_ZAP_IMAGE must be pinned to an immutable sha256 digest"
if [[ "$MODE" == full && "${NAS_ZAP_CONFIRM_ACTIVE:-}" != 1 ]]; then
  die "full active scans require NAS_ZAP_CONFIRM_ACTIVE=1"
fi

if [[ "${NAS_ZAP_ALLOW_PUBLIC_TARGET:-0}" != 1 ]]; then
  python3 - "$TARGET" <<'PY_TARGET' || die "target is not local/private; set NAS_ZAP_ALLOW_PUBLIC_TARGET=1 only for an explicitly authorized target"
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
case "$MODE" in
  baseline)
    scanner=zap-baseline.py
    default_minutes=10
    ;;
  full)
    scanner=zap-full-scan.py
    default_minutes=30
    ;;
esac
minutes="${NAS_ZAP_MAX_MINUTES:-$default_minutes}"
[[ "$minutes" =~ ^[1-9][0-9]*$ ]] || die "NAS_ZAP_MAX_MINUTES must be a positive integer"
(( minutes <= 240 )) || die "NAS_ZAP_MAX_MINUTES must not exceed 240"
process_timeout="${NAS_ZAP_PROCESS_TIMEOUT_SECONDS:-$((minutes * 60 + 120))}"
[[ "$process_timeout" =~ ^[1-9][0-9]*$ ]] || die "NAS_ZAP_PROCESS_TIMEOUT_SECONDS must be a positive integer"
(( process_timeout <= 18000 )) || die "NAS_ZAP_PROCESS_TIMEOUT_SECONDS must not exceed 18000"
[[ "$REPORT_PREFIX" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "NAS_ZAP_REPORT_PREFIX contains unsafe characters"
command -v timeout >/dev/null 2>&1 || die "timeout is required"

runtime_args=(run --rm --network host -v "$OUT_DIR:/zap/wrk:rw")
if [[ -n "${NAS_ZAP_EXTRA_HOST:-}" ]]; then
  [[ "$NAS_ZAP_EXTRA_HOST" != *$'\n'* && "$NAS_ZAP_EXTRA_HOST" != *$'\r'* ]] || die "NAS_ZAP_EXTRA_HOST must be one line"
  runtime_args+=(--add-host "$NAS_ZAP_EXTRA_HOST")
fi

printf 'Running OWASP ZAP %s scan against %s\n' "$MODE" "$TARGET"
set +e
timeout --signal=TERM --kill-after=30s "${process_timeout}s" \
  "$RUNTIME" "${runtime_args[@]}" "$IMAGE" "$scanner" \
    -t "$TARGET" \
    -m "$minutes" \
    -r "zap-$REPORT_PREFIX-$MODE.html" \
    -J "zap-$REPORT_PREFIX-$MODE.json" \
    -w "zap-$REPORT_PREFIX-$MODE.md"
scan_rc=$?
set -e
if [[ "$scan_rc" == 124 || "$scan_rc" == 137 ]]; then
  die "ZAP scan exceeded the outer ${process_timeout}s process deadline"
fi
if (( scan_rc != 0 )); then
  printf 'error: ZAP %s scan failed with exit code %d; warnings are fatal by default\n' "$MODE" "$scan_rc" >&2
  exit "$scan_rc"
fi

for report in "$OUT_DIR/zap-$REPORT_PREFIX-$MODE.html" "$OUT_DIR/zap-$REPORT_PREFIX-$MODE.json" "$OUT_DIR/zap-$REPORT_PREFIX-$MODE.md"; do
  [[ -s "$report" ]] || die "ZAP did not produce expected report: $report"
done
printf 'OWASP ZAP %s scan completed: %s\n' "$MODE" "$OUT_DIR"
