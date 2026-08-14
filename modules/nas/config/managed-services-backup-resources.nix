{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  inherit (nasInternal) failureAlert syncthingConfigDir;
  helpers = import ./managed-services-helpers.nix { inherit lib config nasInternal; };
  inherit (helpers)
    copypartyDataDir
    vaultwardenDataDir
    vaultwardenBackupDir
    backupStage
    authentikArtifact
    copypartyArtifact
    vaultwardenArtifact
    ;

  authentikDump = pkgs.writeShellScript "nas-backup-authentik-dump" ''
    set -euo pipefail
    artifact=${lib.escapeShellArg authentikArtifact}
    install -d -m 0700 "$artifact"
    temporary="$artifact/.database.pgdump.$$"
    trap 'rm -f "$temporary"' EXIT
    ${pkgs.util-linux}/bin/runuser -u postgres -- \
      ${config.services.postgresql.package}/bin/pg_dump --format=custom authentik \
      > "$temporary"
    chmod 0600 "$temporary"
    mv -f "$temporary" "$artifact/database.pgdump"
    trap - EXIT
  '';

  copypartyDump = pkgs.writeShellScript "nas-backup-copyparty-dump" ''
    set -euo pipefail
    source_root=${lib.escapeShellArg "${copypartyDataDir}/copyparty"}
    artifact=${lib.escapeShellArg copypartyArtifact}
    install -d -m 0700 "$artifact"
    ${pkgs.findutils}/bin/find "$artifact" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    ${pkgs.python3}/bin/python3 - "$source_root" "$artifact" <<'PYSQLITEBACKUP'
import pathlib
import sqlite3
import sys

source_root = pathlib.Path(sys.argv[1])
artifact = pathlib.Path(sys.argv[2])
for name in ("shares.db", "sessions.db"):
    source = source_root / name
    if not source.is_file():
        continue
    destination = artifact / name
    with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as source_db:
        with sqlite3.connect(destination) as destination_db:
            source_db.backup(destination_db)
    destination.chmod(0o600)
(artifact / ".complete").write_text("Managed Services V2 CopyParty database dump\n", encoding="utf-8")
(artifact / ".complete").chmod(0o600)
PYSQLITEBACKUP
  '';

  backupResources = {
    authentik-database = {
      path = config.services.postgresql.dataDir;
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "read" ];
      backup = {
        enabled = true;
        consistency = "native-dump";
      };
    };
    authentik-database-dump = {
      path = authentikArtifact;
      scope = "system";
      stateClass = "derived";
      capabilities = [ "read" "write" ];
      backup.enabled = false;
    };
    copyparty-databases = {
      path = copypartyDataDir;
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "read" ];
      backup = {
        enabled = true;
        consistency = "native-dump";
      };
    };
    copyparty-database-dump = {
      path = copypartyArtifact;
      scope = "system";
      stateClass = "derived";
      capabilities = [ "read" "write" ];
      backup.enabled = false;
    };
  }
  // lib.optionalAttrs cfg.syncthing.enable {
    syncthing-config = {
      path = syncthingConfigDir;
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "read" ];
      backup = {
        enabled = true;
        consistency = "filesystem";
      };
    };
  }
  // lib.optionalAttrs cfg.vaultwarden.enable {
    vaultwarden-data = {
      path = vaultwardenDataDir;
      scope = "system";
      stateClass = "authoritative";
      capabilities = [ "read" ];
      backup = {
        enabled = true;
        consistency = "native-dump";
      };
    };
    vaultwarden-dump = {
      path = vaultwardenArtifact;
      scope = "system";
      stateClass = "derived";
      capabilities = [ "read" "write" ];
      backup.enabled = false;
    };
  };

  backupServices = {
    authentik-database-dump = {
      name = "Create a consistent Authentik PostgreSQL dump";
      managed = true;
      workload.kind = "job";
      runtime = {
        type = "systemd";
        unit = "nas-backup-authentik-dump.service";
      };
      storage = [
        {
          resource = "authentik-database";
          mountPath = config.services.postgresql.dataDir;
          access = "read";
        }
        {
          resource = "authentik-database-dump";
          mountPath = authentikArtifact;
          access = "write";
        }
      ];
    };
    copyparty-database-dump = {
      name = "Create consistent CopyParty SQLite dumps";
      managed = true;
      workload.kind = "job";
      runtime = {
        type = "systemd";
        unit = "nas-backup-copyparty-dump.service";
      };
      storage = [
        {
          resource = "copyparty-databases";
          mountPath = copypartyDataDir;
          access = "read";
        }
        {
          resource = "copyparty-database-dump";
          mountPath = copypartyArtifact;
          access = "write";
        }
      ];
    };
  } // lib.optionalAttrs cfg.vaultwarden.enable {
    vaultwarden-dump = {
      name = "Create a consistent Vaultwarden SQLite backup";
      managed = true;
      workload.kind = "job";
      runtime = {
        type = "systemd";
        unit = "backup-vaultwarden.service";
      };
      storage = [
        {
          resource = "vaultwarden-data";
          mountPath = vaultwardenDataDir;
          access = "read";
        }
        {
          resource = "vaultwarden-dump";
          mountPath = vaultwardenArtifact;
          access = "write";
        }
      ];
    };
  };

in
{
  config = {
    systemd.services.nas-backup-authentik-dump = {
      description = "Create a native PostgreSQL dump for Managed Services V2 backup";
      onFailure = failureAlert;
      requires = [ "postgresql.service" ];
      after = [ "postgresql.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = authentikDump;
        UMask = "0077";
      };
    };

    systemd.services.nas-backup-copyparty-dump = {
      description = "Create native SQLite dumps for Managed Services V2 backup";
      onFailure = failureAlert;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = copypartyDump;
        UMask = "0077";
      };
    };

    # nixpkgs supplies the correct SQLite-native Vaultwarden backup service.
    # V2 invokes it synchronously from the Restic preparation transaction, so
    # its independent boot/timer triggers are removed to avoid duplicate backup
    # scheduling and a second policy authority. Priority 90 is enough to beat
    # the module's normal-priority wantedBy without expanding the mkForce policy.
    systemd.services.backup-vaultwarden = lib.mkIf cfg.vaultwarden.enable {
      wantedBy = lib.mkOverride 90 [ ];
    };
    systemd.timers.backup-vaultwarden = lib.mkIf cfg.vaultwarden.enable {
      wantedBy = lib.mkOverride 90 [ ];
    };
  };
}
