{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikApiTokenFile
    authentikEnvironmentFile
    bootstrapAuthentikDataDir
    bootstrapRuntimeRoot
    bootstrapSecretsDir
    cfg
  ;

  bootstrapDatabase = "${bootstrapSecretsDir}/NAS.kdbx";
  bootstrapPasswordFile = "${bootstrapRuntimeRoot}/kdbx-password";
  bootstrapEnvironmentFile = "${bootstrapAuthentikDataDir}/environment";
  bootstrapApiTokenFile = "${bootstrapAuthentikDataDir}/api-token";

  preflight = pkgs.writeShellScript "nas-secret-file-preflight" ''
    set -euo pipefail

    fail() {
      echo "nas-secret-file-preflight: $*" >&2
      exit 78
    }

    require_private_file() {
      local path="$1" label="$2" allowed_mode="$3" owner_policy="$4" group_policy="$5"
      [[ ! -L "$path" ]] || fail "$label must not be a symlink: $path"
      [[ -f "$path" ]] || fail "$label must be a regular file: $path"

      local uid gid mode permissions allowed admin_user admin_uid="" expected_uid="" expected_gid=""
      uid="$(${pkgs.coreutils}/bin/stat -c '%u' -- "$path")" || fail "unable to inspect owner for $label: $path"
      gid="$(${pkgs.coreutils}/bin/stat -c '%g' -- "$path")" || fail "unable to inspect group for $label: $path"
      mode="$(${pkgs.coreutils}/bin/stat -c '%a' -- "$path")" || fail "unable to inspect mode for $label: $path"
      permissions=$((8#$mode))
      allowed=$((8#$allowed_mode))
      (( (permissions & 8#007) == 0 )) || fail "$label grants access to other users: $path ($mode)"
      (( (permissions & ~allowed) == 0 )) || fail "$label permissions exceed the allowed $allowed_mode mask: $path ($mode)"

      case "$owner_policy" in
        root)
          [[ "$uid" == 0 ]] || fail "$label must be owned by root: $path"
          ;;
        admin)
          if [[ -f /var/lib/nas-setup/local-administrator.json && ! -L /var/lib/nas-setup/local-administrator.json ]]; then
            admin_user="$(${pkgs.jq}/bin/jq -er '.username | strings' /var/lib/nas-setup/local-administrator.json 2>/dev/null || true)"
            if [[ -n "$admin_user" ]]; then
              admin_uid="$(${pkgs.glibc.bin}/bin/getent passwd "$admin_user" | ${pkgs.coreutils}/bin/cut -d: -f3 || true)"
            fi
          fi
          [[ "$uid" == 0 || ( -n "$admin_uid" && "$uid" == "$admin_uid" ) ]] \
            || fail "$label must be owned by root or the configured local administrator: $path"
          ;;
        *)
          expected_uid="$(${pkgs.glibc.bin}/bin/getent passwd "$owner_policy" | ${pkgs.coreutils}/bin/cut -d: -f3 || true)"
          [[ -n "$expected_uid" && "$uid" == "$expected_uid" ]] \
            || fail "$label must be owned by $owner_policy: $path"
          ;;
      esac

      if (( permissions & 8#070 )); then
        [[ "$group_policy" != "-" ]] || fail "$label must not grant group permissions: $path ($mode)"
        expected_gid="$(${pkgs.glibc.bin}/bin/getent group "$group_policy" | ${pkgs.coreutils}/bin/cut -d: -f3 || true)"
        [[ -n "$expected_gid" && "$gid" == "$expected_gid" ]] \
          || fail "$label group-readable permissions require group $group_policy: $path"
      fi
    }

    if [[ ! -e /var/lib/nas-setup/operational-runtime-select && ! -e /var/lib/nas-setup/state.json ]]; then
      require_private_file ${lib.escapeShellArg bootstrapDatabase} "bootstrap KDBX" 0600 root -
      require_private_file ${lib.escapeShellArg bootstrapPasswordFile} "bootstrap KDBX password" 0400 root -
      require_private_file ${lib.escapeShellArg bootstrapEnvironmentFile} "bootstrap Authentik environment" 0640 root authentik
      require_private_file ${lib.escapeShellArg bootstrapApiTokenFile} "bootstrap Authentik API token" 0400 root -
      exit 0
    fi

    # A freshly created permanent KDBX is root:nas-administrators 0660 so the
    # setup transaction can hand it to the administrator group without making
    # it world-readable. Restored databases may instead be 0600 and owned by
    # the configured administrator; both representations are intentionally
    # accepted, but group-readable state is accepted only for nas-administrators.
    require_private_file ${lib.escapeShellArg cfg.secrets.keepassDatabase} "permanent KDBX" 0660 admin nas-administrators
    ${lib.optionalString (cfg.secrets.keepassKeyFile != null) ''
      require_private_file ${lib.escapeShellArg cfg.secrets.keepassKeyFile} "KeePass key file" 0600 admin -
    ''}

    if [[ -e ${lib.escapeShellArg authentikEnvironmentFile} || -e ${lib.escapeShellArg authentikApiTokenFile} ]]; then
      require_private_file ${lib.escapeShellArg authentikEnvironmentFile} "permanent Authentik environment" 0400 authentik -
      require_private_file ${lib.escapeShellArg authentikApiTokenFile} "permanent Authentik API token" 0400 root -
    fi
  '';
in
{
  systemd.services.nas-secret-file-preflight = {
    description = "Validate NAS bootstrap and permanent secret-file metadata before runtime activation";
    requires = lib.optional cfg.firstStart.enable "nas-bootstrap-authentik-secrets.service";
    after = lib.optional cfg.firstStart.enable "nas-bootstrap-authentik-secrets.service";
    before = [ "nas-bootstrap-runtime-select.service" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = preflight;
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ReadOnlyPaths = [
        "-/var/lib/nas-bootstrap"
        "-/var/lib/nas-operational"
        "-/var/lib/nas-secrets"
        "-/var/lib/nas-setup"
      ];
      RestrictAddressFamilies = [ "AF_UNIX" ];
      UMask = "0077";
    };
  };

  systemd.services.nas-bootstrap-runtime-select = {
    requires = [ "nas-secret-file-preflight.service" ];
    after = [ "nas-secret-file-preflight.service" ];
  };
}