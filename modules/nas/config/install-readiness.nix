{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  adminAuthorizedKeys = lib.attrByPath [ cfg.adminUser "openssh" "authorizedKeys" "keys" ] [ ] config.users.users;
  adminAuthorizedKeyFiles = lib.attrByPath [ cfg.adminUser "openssh" "authorizedKeys" "keyFiles" ] [ ] config.users.users;
  sshRecoveryConfigured =
    config.services.openssh.enable
    && (adminAuthorizedKeys != [ ] || adminAuthorizedKeyFiles != [ ]);

  runtimeInputValidation = pkgs.writeShellScript "nas-installation-input-validation" ''
    set -euo pipefail

    check_file() {
      local path="$1" label="$2" policy="$3" mode permissions owner
      if [[ -L "$path" ]]; then
        echo "$label must not be a symlink: $path" >&2
        exit 1
      fi
      if [[ ! -f "$path" ]]; then
        echo "$label is missing or is not a regular file: $path" >&2
        exit 1
      fi
      mode="$(${pkgs.coreutils}/bin/stat -c '%a' -- "$path")"
      permissions=$((8#$mode))
      owner="$(${pkgs.coreutils}/bin/stat -c '%u' -- "$path")"
      case "$policy" in
        private)
          if (( permissions & 0077 )); then
            echo "$label must not grant group/other permissions: $path (mode $mode)" >&2
            exit 1
          fi
          ;;
        root-private)
          if [[ "$owner" != 0 ]] || (( permissions & 0077 )); then
            echo "$label must be root-owned and private: $path (uid $owner mode $mode)" >&2
            exit 1
          fi
          ;;
        root-config)
          if [[ "$owner" != 0 ]] || (( permissions & 0022 )); then
            echo "$label must be root-owned and not group/other writable: $path (uid $owner mode $mode)" >&2
            exit 1
          fi
          ;;
        *)
          echo "internal error: unknown file policy $policy" >&2
          exit 2
          ;;
      esac
    }

    check_file ${lib.escapeShellArg cfg.secrets.keepassDatabase} "KeePassXC database" private
    ${lib.optionalString (cfg.secrets.keepassKeyFile != null) ''
      check_file ${lib.escapeShellArg cfg.secrets.keepassKeyFile} "KeePassXC key file" private
    ''}
    ${lib.optionalString (cfg.adminPasswordHashFile != null) ''
      check_file ${lib.escapeShellArg cfg.adminPasswordHashFile} "administrator password hash" root-private
    ''}
    ${lib.optionalString cfg.firstStart.enable ''
      check_file ${lib.escapeShellArg cfg.firstStart.configFile} "first-start configuration" root-config
    ''}
    ${lib.optionalString cfg.backup.enable ''
      check_file ${lib.escapeShellArg cfg.backup.passwordFile} "Restic password file" private
      ${lib.optionalString (cfg.backup.repositoryFile != "") ''
        check_file ${lib.escapeShellArg cfg.backup.repositoryFile} "Restic repository file" private
      ''}
      ${lib.optionalString (cfg.backup.remote.enable && cfg.backup.remote.rcloneConfigFile != "") ''
        check_file ${lib.escapeShellArg cfg.backup.remote.rcloneConfigFile} "rclone configuration" private
      ''}
    ''}
    ${lib.optionalString cfg.power.ups.enable ''
      check_file ${lib.escapeShellArg cfg.power.ups.passwordFile} "UPS password file" private
    ''}
  '';
in
{
  options.nas = {
    hostPolicy.consoleRecoveryVerified = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Operator attestation that a tested local console or hardware-KVM path
        can reach the configured Linux administrator if SSH key recovery is
        unavailable. Set this only after exercising the recovery path.
      '';
    };

    zfsEncryption.acknowledgeUnencrypted = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Explicitly acknowledge that the managed ZFS dataset will be usable
        without data-at-rest encryption. Required for installationReady when
        nas.zfsEncryption.enable is false.
      '';
    };
  };

  config = {
    assertions = [
      {
        assertion =
          !cfg.installationReady
          || sshRecoveryConfigured
          || cfg.hostPolicy.consoleRecoveryVerified;
        message = "installationReady requires an administrator SSH key with OpenSSH enabled or nas.hostPolicy.consoleRecoveryVerified = true after a tested console/KVM recovery drill.";
      }
      {
        assertion = !cfg.installationReady || cfg.adminPasswordHashFile != null;
        message = "installationReady requires nas.adminPasswordHashFile so the local recovery administrator has a declarative PAM credential.";
      }
      {
        assertion =
          !cfg.installationReady
          || cfg.zfsEncryption.enable
          || cfg.zfsEncryption.acknowledgeUnencrypted;
        message = "ZFS encryption is disabled. Enable nas.zfsEncryption.enable or explicitly set nas.zfsEncryption.acknowledgeUnencrypted = true after accepting the data-at-rest risk.";
      }
    ];

    warnings =
      lib.optional (!cfg.zfsEncryption.enable)
        "WARNING: ZFS native encryption is DISABLED. First-start will create/use an unencrypted managed dataset unless encryption is enabled before storage creation."
      ++ lib.optional (cfg.installationReady && !cfg.zfsEncryption.enable && cfg.zfsEncryption.acknowledgeUnencrypted)
        "installationReady explicitly accepts an unencrypted managed ZFS dataset. Data at rest is not protected by ZFS native encryption."
      ++ lib.optional (cfg.autoUpdate.enable && !cfg.autoUpdate.apply)
        "Automatic update checks/builds are scheduled, but automatic activation is disabled because nas.autoUpdate.apply = false."
      ++ lib.optional (cfg.installationReady && cfg.hostPolicy.consoleRecoveryVerified && !sshRecoveryConfigured)
        "installationReady relies on the operator-attested console/KVM recovery path because no administrator SSH key recovery path is configured.";

    systemd.services.nas-installation-input-validation = lib.mkIf (cfg.installationReady && !cfg.testing.installationReadyFixture) {
      description = "Validate installation-ready NAS secret and bootstrap inputs";
      before = [ "nas-protected-services.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = runtimeInputValidation;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [ "AF_UNIX" ];
        UMask = "0077";
      };
    };

    systemd.targets.nas-protected-services = lib.mkIf (cfg.installationReady && !cfg.testing.installationReadyFixture) {
      requires = [ "nas-installation-input-validation.service" ];
      after = [ "nas-installation-input-validation.service" ];
    };
  };
}
