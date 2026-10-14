# shellcheck shell=bash
set -Eeuo pipefail

lib_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
zap_home="$(mktemp -d)"
python3 "$lib_dir/zap-addons.py" prepare --home "$zap_home"
zap.sh -cmd -silent -dir "$zap_home" -addonlist
python3 "$lib_dir/zap-addons.py" verify-loaded --home "$zap_home" --evidence "${NAS_ZAP_ADDON_EVIDENCE:?}"
case "$1" in
  zap-baseline.py|zap-full-scan.py) exec "$@" -z "-silent -dir $zap_home" ;;
  zap.sh) exec "$@" -silent -dir "$zap_home" ;;
  *) printf 'error: unsupported ZAP command: %s\n' "$1" >&2; exit 2 ;;
esac
