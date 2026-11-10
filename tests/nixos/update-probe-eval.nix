# Evaluate nas.update.externalProbeCommand through the exported module and
# require the installed nas-update wrapper to carry exactly the configured argv.
let
  root = builtins.getEnv "NAS_NEGATIVE_ROOT";
  flake = builtins.getFlake root;
  inherit (flake.inputs.nixpkgs) lib;
  evaluate = extra: flake.inputs.nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      flake.nixosModules.default
      (builtins.toPath "${root}/tests/nixos/hardware-configuration.nix")
      (builtins.toPath "${root}/tests/nixos/module-consumer.nix")
      extra
    ];
  };
  probe = [ "/run/current-system/sw/bin/ssh" "-o" "BatchMode=yes" "probe@monitor.invalid" "check nas; $(not-code)" ];
  configured = evaluate {
    nas.update.externalProbeCommand = probe;
    nas.autoUpdate.enable = lib.mkOverride 10 true;
    nas.autoUpdate.apply = true;
  };
  unconfigured = evaluate { };
  internal = system: system.config._module.args.nasInternal;
  exportLine = json: "export NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON=${lib.escapeShellArg json}\n";
  checks = {
    configuredJsonPreservesArgv = builtins.fromJSON (internal configured).updateExternalProbeJson == probe;
    configuredWrapperExportsProbe =
      lib.hasInfix (exportLine (internal configured).updateExternalProbeJson) (internal configured).nasUpdate.text;
    configuredAutoApplyEvaluates = lib.hasSuffix ".drv" configured.config.system.build.toplevel.drvPath;
    unconfiguredIsEmpty = (internal unconfigured).updateExternalProbeJson == "";
    unconfiguredWrapperOverridesAmbientValue =
      lib.hasInfix (exportLine "") (internal unconfigured).nasUpdate.text;
  };
  failed = lib.attrNames (lib.filterAttrs (_: passed: !passed) checks);
in
assert lib.assertMsg (failed == [ ]) ("update probe evaluation cases failed: " + lib.concatStringsSep ", " failed);
checks
