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

  # The KeePass secret system: nas-secrets, nas-unlock-api and
  # nas-keepass-setup. Regenerate vendorHash with scripts/go-vendor-hash.py
  # after a go.mod change.
  nasKeepass = pkgs.buildGoModule {
    pname = "nas-keepass";
    version = lib.removeSuffix "\n" (builtins.readFile ../../../VERSION);
    src = lib.cleanSource ../../../go;
    vendorHash = "sha256-cO051trct9jCpF7swRL2ed1nyN1DeUwXPfgjZnq1ZBs=";
    subPackages = [
      "cmd/nas-keepass-setup"
      "cmd/nas-secrets"
      "cmd/nas-unlock-api"
    ];
    env.CGO_ENABLED = 0;
    ldflags = [ "-s" "-w" ];
    # The compile-fail typestate test needs a writable module tree.
    checkFlags = [ "-short" ];
    meta.mainProgram = "nas-secrets";
  };

  # Non-secret settings only: paths, unit names and optional consumers.
  nasSecretsConfig = pkgs.writeText "nas-secrets.json" (builtins.toJSON {
    schemaVersion = 1;
    database = cfg.secrets.keepassDatabase;
    keyFile = if cfg.secrets.keepassKeyFile == null then "" else cfg.secrets.keepassKeyFile;
    group = cfg.secrets.keepassGroup;
    inherit secretRoot;
    runtimeRoot = "/run/nas-secret-runtime";
    lockFile = "/run/lock/nas-secrets.lock";
    setupState = "/var/lib/nas-setup/state.json";
    protectedTarget = "nas-protected-services.target";
    v2SystemdState = "/run/nas-control/systemd-reconciled.json";
    bootstrapAuthentikDir = bootstrapAuthentikDataDir;
    inherit authentikRuntimeEnvironmentFile authentikUnlockedEnvironmentFile authentikRuntimeOutpostTokenFile;
    authentikApiTokenFile = authentikApiTokenFile;
    authentikRuntimeApiTokenFile = authentikRuntimeApiTokenFile;
    authentikReadyUrl = "http://127.0.0.1:${toString authentikPort}${cfg.identity.authentikPath}-/health/ready/";
    bootstrapEmail = cfg.identity.bootstrapEmail;
    operationRunner = "/run/current-system/sw/bin/nas-operation-run";
    features = {
      observability = cfg.observability.enable;
      grafana = cfg.observability.enable && cfg.observability.grafana.enable;
      ntfy = cfg.observability.ntfy.enable;
      nutWeb = cfg.power.ups.enable && cfg.power.ups.web.enable;
      zfsEncryption = cfg.zfsEncryption.enable;
      vaultwarden = cfg.vaultwarden.enable;
    };
  });

  nasSecrets = pkgs.writeShellApplication {
    name = "nas-secrets";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.keepassxc
      pkgs.systemd
    ];
    text = ''
      export PATH=/run/wrappers/bin:$PATH
      export NAS_SECRETS_CONFIG=${nasSecretsConfig}
      exec ${nasKeepass}/bin/nas-secrets "$@"
    '';
  };

  nasKeepassSetup = pkgs.writeShellApplication {
    name = "nas-keepass-setup";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.keepassxc
      pkgs.util-linux
    ];
    text = ''
      export PATH=/run/wrappers/bin:$PATH
      exec ${nasKeepass}/bin/nas-keepass-setup "$@"
    '';
  };
in
{
  inherit nasKeepass nasKeepassSetup nasSecrets nasSecretsConfig;
}
