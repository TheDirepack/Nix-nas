{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cfg
  ;
in
{
  config = {
    virtualisation.podman.enable = true;
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
