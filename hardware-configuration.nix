# Replace this repository placeholder with reviewed nixos-generate-config output
# for the actual target host before setting nas.installationReady = true.

{ config, ... }:

{
  # The generated hardware configuration will overwrite this file and therefore
  # remove the stub marker. installationReady fails closed while this marker is
  # present, even if root filesystem settings are supplied somewhere else.
  nas.testing.hardwareConfigurationStub = true;
  assertions = [
    {
      assertion = !config.nas.installationReady;
      message = "hardware-configuration.nix is still the repository placeholder. Replace it with reviewed nixos-generate-config output before setting nas.installationReady = true.";
    }
  ];
}
