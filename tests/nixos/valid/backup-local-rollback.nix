{ config, lib, pkgs, ... }:

let
  policy = builtins.fromJSON config.environment.etc."nas-control/backup-policy.json".text;
  backupUnit = config.systemd.services.restic-backups-nas-boot-system;
in
{
  nas.backup = {
    enable = lib.mkOverride 10 true; # module-consumer.nix forces it off
    passwordFile = "/run/secrets/restic-password";
    allowSamePoolRepository = true;
  };

  assertions = [
    {
      assertion =
        policy.repositorySource == "local"
        && policy.repositoryFile == null
        && policy.localRepository == "${config.nas.zfsRoot}/backups/restic-system"
        && config.services.restic.backups.nas-boot-system.repository == policy.localRepository;
      message = "backup fixture: an acknowledged local repository must stay on the managed pool path.";
    }
    {
      assertion =
        lib.elem "nas-zfs-mount-guard.service" backupUnit.requires
        && !(lib.elem pkgs.rclone backupUnit.path);
      message = "backup fixture: a local repository requires the pool mount and no rclone.";
    }
  ];
}
