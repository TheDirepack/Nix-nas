{ lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikRuntimeApiTokenFile
    authentikRuntimeEnvironmentFile
    bootstrapRuntimeRoot
  ;
  materializeBootstrapCredentials = pkgs.writeShellScript "nas-bootstrap-materialize-runtime-credentials" ''
    set -euo pipefail
    umask 0077

    # Permanent credentials are generated only after the fresh permanent KDBX
    # exists, so keep their late-bound symlinks. Bootstrap credentials already
    # exist and can be staged as ordinary private /run files. This both narrows
    # the runtime trust boundary and lets first-run verify the staged token with
    # O_NOFOLLOW/lstat semantics.
    if [[ -e /var/lib/nas-setup/operational-runtime-select || -e /var/lib/nas-setup/state.json ]]; then
      exit 0
    fi

    materialize() {
      local source="$1" destination="$2" mode="$3" owner="$4" group="$5"
      case "$source" in
        ${lib.escapeShellArg bootstrapRuntimeRoot}/*) ;;
        *) echo "Bootstrap credential source escaped bootstrap runtime: $source" >&2; exit 79 ;;
      esac
      if [[ -L "$source" || ! -f "$source" ]]; then
        echo "Bootstrap credential source must be a regular non-symlink file: $source" >&2
        exit 79
      fi
      if [[ -e "$destination" && ! -L "$destination" ]]; then
        echo "Refusing unexpected bootstrap runtime credential path: $destination" >&2
        exit 79
      fi
      tmp="$(${pkgs.coreutils}/bin/mktemp /run/nas-authentik/.credential.XXXXXX)"
      trap '${pkgs.coreutils}/bin/rm -f -- "$tmp"' RETURN
      ${pkgs.coreutils}/bin/install -m "$mode" -o "$owner" -g "$group" "$source" "$tmp"
      ${pkgs.coreutils}/bin/mv -T -- "$tmp" "$destination"
      trap - RETURN
    }

    materialize \
      ${lib.escapeShellArg "${bootstrapRuntimeRoot}/authentik/environment"} \
      ${lib.escapeShellArg authentikRuntimeEnvironmentFile} \
      0640 root authentik
    materialize \
      ${lib.escapeShellArg "${bootstrapRuntimeRoot}/authentik/api-token"} \
      ${lib.escapeShellArg authentikRuntimeApiTokenFile} \
      0400 root root
  '';
in
{
  systemd.services.nas-bootstrap-runtime-select.serviceConfig.ExecStartPost =
    lib.mkAfter [ materializeBootstrapCredentials ];
}
