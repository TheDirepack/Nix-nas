{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cfg
  ;
  containersLegacyPath = "/var/lib/containers";
  containersStoragePath = "${cfg.zfsRoot}/containers/storage";
  containersStorageCheck = pkgs.writeShellScript "nas-containers-storage-check" ''
    set -euo pipefail
    legacy=${lib.escapeShellArg containersLegacyPath}
    graphroot=${lib.escapeShellArg containersStoragePath}

    if [[ -L "$legacy" || ! -d "$legacy" ]]; then
      exit 0
    fi
    if [[ -z "$(${pkgs.coreutils}/bin/ls -A "$legacy")" ]]; then
      exit 0
    fi

    echo "Legacy Podman storage is present at $legacy, but the configured graphroot is $graphroot." >&2
    echo "Starting Podman now would silently ignore the existing containers and images." >&2
    echo "Migrate the data while Podman is stopped, for example:" >&2
    echo "  install -d -m 0710 -o root -g root $graphroot" >&2
    echo "  cp -a --reflink=auto $legacy/. $graphroot/" >&2
    echo "  rm -rf --one-file-system $legacy" >&2
    echo "Then reboot so the storage symlink is created. To keep the legacy location" >&2
    echo "instead, disable nas.virtualization.enable." >&2
    exit 1
  '';
in
{
  config = lib.mkMerge [
    (lib.mkIf cfg.virtualization.enable {
      systemd.tmpfiles.rules = [
        "d ${cfg.zfsRoot}/containers 0755 root root -"
        "d ${cfg.zfsRoot}/containers/storage 0710 root root -"
        # L (without +): only create the symlink when absent, so existing Podman
        # storage under /var/lib/containers is never deleted or replaced.
        "L /var/lib/containers - - - - ${containersStoragePath}"
      ];

      # The symlink above cannot replace a pre-existing directory, so a legacy
      # graphroot would be ignored silently. Fail loudly instead, and keep
      # Podman from starting until the operator migrates or reverts.
      systemd.services.nas-containers-storage-check = {
        description = "Check for Podman storage left at the legacy graphroot";
        wantedBy = [ "multi-user.target" ];
        before = [ "podman.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = containersStorageCheck;
        };
      };
      systemd.services.podman = {
        requires = [ "nas-containers-storage-check.service" ];
        after = [ "nas-containers-storage-check.service" ];
      };
    })

    {
      virtualisation.podman.enable = true;
      virtualisation.containers.storage.settings = lib.mkIf cfg.virtualization.enable {
        storage = {
          driver = "overlay";
          graphroot = containersStoragePath;
          runroot = "/run/containers/storage";
        };
      };
      virtualisation.libvirtd = lib.mkIf cfg.virtualization.enable {
        enable = true;
        onShutdown = "shutdown";
        shutdownTimeout = 180;
        parallelShutdown = 2;
        allowedBridges = cfg.virtualization.allowedBridges;
        qemu = {
          package = pkgs.qemu_kvm;
          runAsRoot = cfg.virtualization.runAsRoot;
          swtpm.enable = cfg.virtualization.swtpm;
          vhostUserPackages = lib.optional cfg.virtualization.virtiofs pkgs.virtiofsd;
        };
      };
    }
  ];
}
