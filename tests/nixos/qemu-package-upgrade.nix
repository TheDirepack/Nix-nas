{ ... }:

let
  # Linux 6.18.63 includes the x86 text-patching fix first shipped in 6.18.53.
  kernelSource = builtins.fetchTarball {
    url = "https://codeload.github.com/NixOS/nixpkgs/tar.gz/f68407657ad294471eb4b2e65d193df26edf729f";
    sha256 = "sha256-E+XLAfnC7+bdr4qlEgRv6cdGmiqTU5oeFNKCha7epqQ=";
  };
  kernelPkgs = import kernelSource { system = "x86_64-linux"; };
in
{
  boot.kernelPackages = kernelPkgs.linuxPackages_6_18;

  # NixOS selects the ZFS module from boot.kernelPackages. Use the same
  # pin for userspace so appliance commands use the matching ZFS release.
  nixpkgs.overlays = [
    (_: _: { inherit (kernelPkgs) zfs; })
  ];
}
