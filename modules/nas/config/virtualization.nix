{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cfg
  ;
in
{
  config = {
    systemd.tmpfiles.rules = lib.mkIf cfg.virtualization.enable [
      "d ${cfg.zfsRoot}/containers 0755 root root -"
      "d ${cfg.zfsRoot}/containers/storage 0710 root root -"
      "L+ /var/lib/containers - - - - ${cfg.zfsRoot}/containers/storage"
    ];

    virtualisation.podman.enable = true;
    virtualisation.containers.storage.settings = lib.mkIf cfg.virtualization.enable {
      storage = {
        driver = "overlay";
        graphroot = "${cfg.zfsRoot}/containers/storage";
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
  };
}
