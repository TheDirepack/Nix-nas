{ lib }:

let
  policyFor = import ../../modules/nas/internal/backup-policy.nix { inherit lib; };
  repositoryFile = "/run/secrets/restic-repository";
  rcloneConfig = "/run/secrets/rclone.conf";
  cfgFor = {
    backup ? { },
    installationReady ? false,
    fixture ? false,
    replication ? false,
  }: {
    inherit installationReady;
    testing.installationReadyFixture = fixture;
    zfsReplication.enable = replication;
    zfsPool = "tank";
    zfsRoot = "/tank";
    secrets.keepassDatabase = "/var/lib/nas-control-plane/nas-secrets/NAS.kdbx";
    backup = lib.recursiveUpdate {
      enable = true;
      passwordFile = "/run/secrets/restic-password";
      repositoryFile = "";
      localRepository = "";
      rcloneConfigFile = "";
      allowSamePoolRepository = false;
      restoreVerification.enable = true;
    } backup;
  };
  policy = args: policyFor (cfgFor args);
  failures = args: map (assertion: assertion.message) (lib.filter (assertion: !assertion.assertion) (policy args).assertions);
  messages = lib.listToAttrs (lib.zipListsWith
    (name: assertion: lib.nameValuePair name assertion.message)
    [ "password" "local" "ready" "rclone" "paths" ]
    (policy { }).assertions);

  # Option migration is checked against the real option module, with only the
  # NixOS assertion/warning sinks stubbed.
  sinks = {
    options.assertions = lib.mkOption { type = lib.types.listOf lib.types.unspecified; default = [ ]; };
    options.warnings = lib.mkOption { type = lib.types.listOf lib.types.str; default = [ ]; };
  };
  migrate = definitions: (lib.evalModules {
    modules = [ sinks ../../modules/nas/options/operations.nix { config.nas.backup = definitions; } ];
  }).config;
  migrationFailures = definitions:
    map (assertion: assertion.message) (lib.filter (assertion: !assertion.assertion) (migrate definitions).assertions);
  rejectsWith = text: definitions: lib.any (lib.hasInfix text) (migrationFailures definitions);

  checks = {
    messageNamesCoverEveryAssertion = lib.length (policy { }).assertions == lib.length (lib.attrNames messages);
    repositoryFileIsInstallationReady =
      failures { backup.repositoryFile = repositoryFile; installationReady = true; } == [ ];
    implicitLocalRepositoryRejected = failures { } == [ messages.local ];
    acknowledgedLocalRepositoryIsRollbackOnly = failures { backup.allowSamePoolRepository = true; } == [ ];
    acknowledgedLocalRepositoryIsNotInstallationReady =
      failures { backup.allowSamePoolRepository = true; installationReady = true; } == [ messages.ready ];
    explicitLocalRepositoryIsNotIndependent =
      failures { backup.localRepository = "/mnt/usb/restic"; installationReady = true; }
      == [ messages.local messages.ready ];
    replicationSatisfiesInstallationReady =
      failures { backup.allowSamePoolRepository = true; installationReady = true; replication = true; } == [ ];
    disabledBackupIsNotInstallationReady = failures { backup.enable = false; installationReady = true; } == [ messages.ready ];
    disabledBackupWithReplicationIsInstallationReady =
      failures { backup.enable = false; installationReady = true; replication = true; } == [ ];
    disabledBackupDoesNotRequireAcknowledgement = failures { backup.enable = false; } == [ ];
    readinessFixtureSkipsOnlyTheReadinessGate =
      failures { installationReady = true; fixture = true; } == [ messages.local ];
    rcloneConfigWithRepositoryFile =
      failures { backup.repositoryFile = repositoryFile; backup.rcloneConfigFile = rcloneConfig; } == [ ];
    rcloneConfigWithoutRepositoryFileRejected =
      failures { backup.allowSamePoolRepository = true; backup.rcloneConfigFile = rcloneConfig; } == [ messages.rclone ];
    relativeRcloneConfigRejected =
      failures { backup.repositoryFile = repositoryFile; backup.rcloneConfigFile = "rclone.conf"; } == [ messages.paths ];
    relativeRepositoryFileRejected = failures { backup.repositoryFile = "restic-repository"; } == [ messages.paths ];
    missingPasswordRejected =
      failures { backup.repositoryFile = repositoryFile; backup.passwordFile = ""; } == [ messages.password messages.paths ];

    repositoryFilePolicy =
      let
        selected = policy { backup.repositoryFile = repositoryFile; };
      in
      !selected.usesLocalRepository
      && selected.independentCopyConfigured
      && selected.runtime.repositorySource == "repository-file"
      && selected.runtime.repositoryFile == repositoryFile
      && !(selected.runtime ? repository);
    localPolicy =
      let
        selected = policy { backup.allowSamePoolRepository = true; };
      in
      selected.usesLocalRepository
      && !selected.independentCopyConfigured
      && selected.runtime.repositorySource == "local"
      && selected.runtime.repositoryFile == null
      && selected.runtime.localRepository == "/tank/backups/restic-system";
    disabledRestoreVerificationInRuntime =
      !(policy { backup.enable = false; }).runtime.restoreVerification;

    renamedRcloneConfigFileMigrates =
      let
        migrated = migrate { remote.rcloneConfigFile = rcloneConfig; };
      in
      migrated.nas.backup.rcloneConfigFile == rcloneConfig
      && migrationFailures { remote.rcloneConfigFile = rcloneConfig; } == [ ]
      && migrated.warnings != [ ];
    retiredRemoteEnableRejected = rejectsWith "nas.backup.repositoryFile" { remote.enable = true; };
    retiredRemoteDisabledStillRejected = rejectsWith "nas.backup.repositoryFile" { remote.enable = false; };
    retiredProviderRejected = rejectsWith "rclone:<provider>:nas-backup" { remote.provider = "gdrive"; };
    retiredRcloneRemoteRejected = rejectsWith "nas.backup.repositoryFile" { remote.rcloneRemote = "gdrive:nas"; };
    retiredScopeRejected = rejectsWith "never limited what was backed up" { remote.scope = "all"; };
    currentOptionsMigrateCleanly = migrationFailures { repositoryFile = repositoryFile; } == [ ];
  };
  failed = lib.attrNames (lib.filterAttrs (_: passed: !passed) checks);
in
assert lib.assertMsg (failed == [ ]) ("backup policy cases failed: " + lib.concatStringsSep ", " failed);
checks
