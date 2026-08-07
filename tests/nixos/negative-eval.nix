{ root, fixture }:

let
  flake = builtins.getFlake root;
  fixturePath = builtins.toPath "${root}/${fixture}";
  system = flake.inputs.nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      flake.nixosModules.default
      (builtins.toPath "${root}/tests/nixos/hardware-configuration.nix")
      (builtins.toPath "${root}/tests/nixos/module-consumer.nix")
      fixturePath
    ];
  };
in
system.config.system.build.toplevel.drvPath
