# configuration.nix for the harness VM ("nas-vm").
#
# Deliberately minimal and VM-shaped: sshd + root key login, an `admin` user
# with passwordless sudo, and flakes enabled. The project flake is NOT wired in
# yet — adapting the real `nas` configuration for the VM is a later stage.
# __HARNESS_PUBLIC_KEY__ is replaced at provisioning-image build time.
{ config, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];

  boot.loader.grub = {
    enable = true;
    devices = [ "/dev/vda" ];
  };
  boot.loader.timeout = 5;

  networking.hostName = "nas-vm";
  networking.useDHCP = true;

  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "yes";
    };
  };

  users.users.root.openssh.authorizedKeys.keys = [
    "__HARNESS_PUBLIC_KEY__"
  ];

  users.users.admin = {
    isNormalUser = true;
    initialPassword = "admin";
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [
      "__HARNESS_PUBLIC_KEY__"
    ];
  };

  security.sudo.wheelNeedsPassword = false;

  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  environment.systemPackages = [ pkgs.git ];

  system.stateVersion = "26.05";
}
