# Pure Restic repository policy shared by evaluation-time validation, the
# Restic units, and the runtime policy consumed by nas-backup-status.
{ lib }:
cfg:
let
  backup = cfg.backup;
  repositoryFileConfigured = backup.repositoryFile != "";
  absoluteWhenSet = value: value == "" || lib.hasPrefix "/" value;
in
rec {
  localRepository =
    if backup.localRepository != "" then backup.localRepository
    else "${cfg.zfsRoot}/backups/restic-system";

  repositorySource = if repositoryFileConfigured then "repository-file" else "local";
  usesLocalRepository = !repositoryFileConfigured;

  # Repository contents are a runtime secret, so evaluation can only see that
  # an off-pool repository was requested; nas-backup-status check-readiness
  # rejects a repository file that names a path on the managed pool.
  offPoolRepositoryRequested = backup.enable && repositoryFileConfigured;
  independentCopyConfigured = offPoolRepositoryRequested || cfg.zfsReplication.enable;

  assertions = [
    {
      assertion = !backup.enable || backup.passwordFile != "";
      message = "Restic boot/system recovery backups require nas.backup.passwordFile.";
    }
    {
      assertion = !backup.enable || repositoryFileConfigured || backup.allowSamePoolRepository;
      message = "nas.backup.localRepository is local rollback storage, not an independent backup. Set nas.backup.repositoryFile to a private file naming an off-pool Restic repository (any Restic backend, including rclone:<remote>:<path>), or set nas.backup.allowSamePoolRepository = true to accept rollback-only protection.";
    }
    {
      assertion = !cfg.installationReady || cfg.testing.installationReadyFixture || independentCopyConfigured;
      message = "installationReady requires an off-pool Restic repository (nas.backup.repositoryFile) or enabled ZFS replication.";
    }
    {
      assertion = backup.rcloneConfigFile == "" || repositoryFileConfigured;
      message = "nas.backup.rcloneConfigFile is used only for an rclone: repository named by nas.backup.repositoryFile.";
    }
    {
      assertion =
        !backup.enable
        || (lib.hasPrefix "/" backup.passwordFile
          && lib.hasPrefix "/" cfg.secrets.keepassDatabase
          && absoluteWhenSet backup.repositoryFile
          && absoluteWhenSet backup.localRepository
          && absoluteWhenSet backup.rcloneConfigFile);
      message = "Restic passwordFile, KDBX path, repositoryFile, localRepository, and rcloneConfigFile must be absolute paths when set.";
    }
  ];

  # Non-secret runtime policy. Never add the repository string: it can embed
  # backend credentials.
  runtime = {
    schemaVersion = 1;
    enabled = backup.enable;
    inherit repositorySource localRepository;
    repositoryFile = if repositoryFileConfigured then backup.repositoryFile else null;
    allowSamePoolRepository = backup.allowSamePoolRepository;
    replication = cfg.zfsReplication.enable;
    restoreVerification = backup.enable && backup.restoreVerification.enable;
    zfsPool = cfg.zfsPool;
    zfsRoot = cfg.zfsRoot;
    recordDirectory = "/var/lib/nas-backup/status";
  };
}
