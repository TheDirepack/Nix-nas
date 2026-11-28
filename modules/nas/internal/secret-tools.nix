args:
let
  inherit (args)
    authentikApiTokenFile
    authentikPort
    authentikRuntimeApiTokenFile
    authentikRuntimeEnvironmentFile
    authentikRuntimeOutpostTokenFile
    authentikUnlockedEnvironmentFile
    bootstrapAuthentikDataDir
    cfg
    lib
    pkgs
    secretRoot
  ;
  zig = import ./zig-toolchain.nix { inherit pkgs; };

  # ZON rendering for the comptime configuration. JSON string literals are
  # valid Zig literals for the printable ASCII the config admits; config.zig
  # rejects control characters and relative paths at compile time.
  zonValue = value:
    if value == null then "null"
    else if builtins.isBool value then (if value then "true" else "false")
    else if builtins.isString value then builtins.toJSON value
    else if builtins.isAttrs value then
      ".{ " + lib.concatStringsSep ", " (lib.mapAttrsToList (name: v: ".${name} = ${zonValue v}") value) + " }"
    else throw "nas-secrets config: unsupported ZON value";

  coreutils = "${pkgs.coreutils}/bin";
  nasSecretsConfig = pkgs.writeText "nas-secrets-config.zon" (zonValue {
    database = cfg.secrets.keepassDatabase;
    key_file = cfg.secrets.keepassKeyFile;
    secret_group = cfg.secrets.keepassGroup;
    secret_root = secretRoot;
    bootstrap_authentik_dir = bootstrapAuthentikDataDir;
    authentik_runtime_environment_file = authentikRuntimeEnvironmentFile;
    authentik_unlocked_environment_file = authentikUnlockedEnvironmentFile;
    authentik_runtime_outpost_token_file = authentikRuntimeOutpostTokenFile;
    authentik_api_token_file = authentikApiTokenFile;
    authentik_runtime_api_token_file = authentikRuntimeApiTokenFile;
    authentik_ready_url = "http://127.0.0.1:${toString authentikPort}${cfg.identity.authentikPath}-/health/ready/";
    bootstrap_email = cfg.identity.bootstrapEmail;
    features = {
      grafana = cfg.observability.enable && cfg.observability.grafana.enable;
      ntfy = cfg.observability.ntfy.enable;
      nut_webgui = cfg.power.ups.enable && cfg.power.ups.web.enable;
      zfs_encryption = cfg.zfsEncryption.enable;
      vaultwarden = cfg.vaultwarden.enable;
      observability_dir = cfg.observability.enable || cfg.observability.ntfy.enable;
    };
    tools = {
      keepassxc_cli = "${pkgs.keepassxc}/bin/keepassxc-cli";
      sudo = "/run/wrappers/bin/sudo";
      systemctl = "${pkgs.systemd}/bin/systemctl";
      install = "${coreutils}/install";
      mktemp = "${coreutils}/mktemp";
      ln = "${coreutils}/ln";
      rm = "${coreutils}/rm";
      mv = "${coreutils}/mv";
      realpath = "${coreutils}/realpath";
      chown = "${coreutils}/chown";
      chmod = "${coreutils}/chmod";
      cat = "${coreutils}/cat";
      test_ = "${coreutils}/test";
      curl = "${pkgs.curl}/bin/curl";
      timeout = "${coreutils}/timeout";
    };
  });

  # nas-secrets, nas-unlock-api and nas-keepass-setup. The activation plan is
  # compiled from this host's options, so the package rebuilds when they change.
  nasKeepassTools = pkgs.stdenv.mkDerivation {
    pname = "nas-keepass-tools";
    version = lib.removeSuffix "\n" (builtins.readFile ../../../VERSION);
    src = lib.fileset.toSource {
      root = ../../../zig;
      fileset = lib.fileset.unions [
        ../../../zig/build.zig
        ../../../zig/build.zig.zon
        ../../../zig/config
        ../../../zig/src
        ../../../zig/tests
      ];
    };
    nativeBuildInputs = [ zig ];
    dontConfigure = true;
    # Baseline CPU: the closure may be built on a newer machine than the NAS.
    zigFlags = [ "-Drelease=true" "-Dtarget=x86_64-linux" "-Dcpu=baseline" "-Dconfig=${nasSecretsConfig}" ];
    buildPhase = ''
      runHook preBuild
      export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global-cache ZIG_LOCAL_CACHE_DIR=$TMPDIR/zig-local-cache
      zig build $zigFlags --prefix $out
      runHook postBuild
    '';
    doCheck = true;
    checkPhase = ''
      runHook preCheck
      zig build test $zigFlags
      zig build compile-errors $zigFlags
      runHook postCheck
    '';
    dontInstall = true;
    dontStrip = true;
    meta.mainProgram = "nas-secrets";
  };

  # Consumers keep using `${nasSecrets}/bin/nas-secrets`.
  nasSecrets = nasKeepassTools;
in
{
  inherit nasKeepassTools nasSecrets;
}
