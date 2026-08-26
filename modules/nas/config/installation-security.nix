{ config, lib, ... }:

let
  cfg = config.nas;
  hasSshRecoveryKey = lib.any
    (user:
      lib.elem "nas-administrators" (user.extraGroups or [ ])
      && (((user.openssh.authorizedKeys.keys or [ ]) != [ ])
        || ((user.openssh.authorizedKeys.keyFiles or [ ]) != [ ])))
    (lib.attrValues config.users.users);
in
{
  options.nas = {
    recovery.consoleOrKvmAvailable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Explicitly attest that a tested local console or out-of-band KVM path
        is available for appliance recovery when SSH is unavailable. Set this
        only after verifying the path on the target hardware.
      '';
    };

    zfsEncryption.disabledAcknowledged = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Explicit acknowledgement that the install-ready NAS will store its
        managed ZFS dataset without native encryption. This does not enable
        encryption; it only prevents an accidental unencrypted deployment.
      '';
    };

    testing.hardwareConfigurationStub = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      visible = false;
      description = "Marks the repository placeholder hardware-configuration.nix so installationReady cannot use it.";
    };
  };

  config = {
    assertions = [
      {
        assertion =
          !cfg.installationReady
          || cfg.testing.installationReadyFixture
          || !cfg.testing.hardwareConfigurationStub;
        message = "installationReady refuses the repository placeholder hardware-configuration.nix; replace it with reviewed nixos-generate-config output for the target host.";
      }
      {
        assertion =
          !cfg.installationReady
          || cfg.testing.installationReadyFixture
          || hasSshRecoveryKey
          || cfg.recovery.consoleOrKvmAvailable;
        message = "installationReady requires a usable recovery path: configure an SSH authorized key for a nas-administrators user, or explicitly attest a tested console/KVM path with nas.recovery.consoleOrKvmAvailable = true.";
      }
      {
        assertion =
          !cfg.installationReady
          || cfg.zfsEncryption.enable
          || cfg.zfsEncryption.disabledAcknowledged;
        message = "installationReady with ZFS encryption disabled requires explicit acknowledgement via nas.zfsEncryption.disabledAcknowledged = true.";
      }
    ];

    warnings = lib.optional (!cfg.zfsEncryption.enable) ''
      SECURITY: native ZFS encryption is DISABLED. Managed application state,
      shares, containers, VMs, and user data on nas.zfsDataset will be stored
      unencrypted. An install-ready deployment must either enable
      nas.zfsEncryption.enable or explicitly acknowledge this state with
      nas.zfsEncryption.disabledAcknowledged = true.
    '';
  };
}
