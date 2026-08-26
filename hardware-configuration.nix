# Replace with reviewed nixos-generate-config output before installation.

{ config, ... }:

{
  assertions = [
    {
      assertion = !config.nas.installationReady;
      message = "hardware-configuration.nix is still the repository placeholder. Replace it with reviewed nixos-generate-config output before setting nas.installationReady = true.";
    }
  ];
}
