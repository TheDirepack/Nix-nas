#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
port="${NAS_HTTP_FUZZ_PORT:-4173}"
base="http://127.0.0.1:${port}"
server_log="$(mktemp)"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -f -- "$server_log"
}
trap cleanup EXIT INT TERM

python3 -m http.server "$port" --bind 127.0.0.1 --directory "$repo_root/cockpit/dist" >"$server_log" 2>&1 &
server_pid=$!

for _ in {1..50}; do
  if curl --silent --fail --max-time 1 "$base/index.html" >/dev/null; then
    break
  fi
  sleep 0.1
done

if ! kill -0 "$server_pid" 2>/dev/null; then
  cat "$server_log" >&2
  exit 1
fi

status() {
  curl --silent --show-error --max-time 10 --output /dev/null --write-out '%{http_code}' "$@"
}

[[ "$(status "$base/index.html")" == "200" ]]
[[ "$(status --head "$base/index.html?probe=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")" == "200" ]]
[[ "$(status "$base/%2e%2e/%2e%2e/etc/passwd")" == "404" ]]
[[ "$(status "$base/%3Cscript%3Ealert(1)%3C%2Fscript%3E.js")" == "404" ]]
[[ "$(status "$base/javascript%3Aalert(1)")" == "404" ]]
[[ "$(status "$base/..%2F..%2Fetc%2Fshadow")" == "404" ]]

printf 'curl HTTP adversarial checks passed\n'
