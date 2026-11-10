{ config, lib, pkgs, ... }:

let
  policy = builtins.fromJSON config.environment.etc."nas-control/backup-policy.json".text;
  backupUnit = config.systemd.services.restic-backups-nas-boot-system;
  verifyUnit = config.systemd.services.nas-backup-restore-verify;
  records = name: unit:
    lib.any
      (command: lib.hasPrefix "-" command && lib.hasSuffix "/bin/nas-backup-status record ${name}" command)
      (map toString (lib.toList (unit.serviceConfig.ExecStopPost or [ ])));
in
{
  nas.backup = {
    enable = lib.mkOverride 10 true; # module-consumer.nix forces it off
    passwordFile = "/run/secrets/restic-password";
    repositoryFile = "/run/secrets/restic-repository";
    # Exercise the explicit rename from the retired remote options.
    remote.rcloneConfigFile = "/run/secrets/rclone.conf";
  };

  assertions = [
    {
      assertion =
        policy.enabled
        && policy.repositorySource == "repository-file"
        && policy.repositoryFile == "/run/secrets/restic-repository"
        && policy.restoreVerification
        && !(policy ? repository);
      message = "backup fixture: the runtime policy must name the repository file, never its contents.";
    }
    {
      assertion = config.services.restic.backups.nas-boot-system.repositoryFile == "/run/secrets/restic-repository";
      message = "backup fixture: Restic must read the repository natively through --repository-file.";
    }
    {
      assertion =
        (backupUnit.environment.RCLONE_CONFIG or null) == "/run/secrets/rclone.conf"
        && (verifyUnit.environment.RCLONE_CONFIG or null) == "/run/secrets/rclone.conf"
        && lib.elem pkgs.rclone backupUnit.path
        && lib.elem pkgs.rclone verifyUnit.path;
      message = "backup fixture: both Restic units need rclone and the renamed rcloneConfigFile.";
    }
    {
      assertion = !(lib.elem "nas-zfs-mount-guard.service" backupUnit.requires);
      message = "backup fixture: an off-pool repository must not require the managed pool mount.";
    }
    {
      assertion = records "backup" backupUnit && records "restore-verify" verifyUnit;
      message = "backup fixture: both Restic units must record their result for nas-backup-status.";
    }
  ];
}
