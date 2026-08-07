args:
let
  inherit (args)
    config
    lib
    pkgs
  ;
  cfg = config.nas;
  serviceRegistry = args.serviceRegistry;
  lanHost = "${config.networking.hostName}.local";
  identityAdminGroup = "nas_admin";
  secretRoot = "/run/nas-secrets";
  authentikSecretDir = "${secretRoot}/authentik";
  authentikEnvironmentFile = "${authentikSecretDir}/environment";
  authentikApiTokenFile = "${authentikSecretDir}/api-token";
  authentikBootstrapTokenFile = "${authentikSecretDir}/bootstrap-token";
  copypartyUserConfigDir = "/var/lib/copyparty/user.d";
  featureCatalogPath = "/etc/nas-control/features.json";
  featureSchemaPath = "/etc/nas-control/feature-catalog.schema.json";
  featureStatePath = "/var/lib/nas-control/settings.json";
  featureRuntimePath = "/run/nas-control/on-demand.json";
  onDemandGateSocket = "/run/nas-on-demand/gate.sock";
  authentikPort = serviceRegistry.identity.port;
  cockpitPort = serviceRegistry.cockpit.port;
  syncthingGuiPort = serviceRegistry.syncthing.port;
  vaultwardenPort = serviceRegistry.vaultwarden.port;
  vaultwardenSecretDir = "${secretRoot}/vaultwarden";
  zfsSecretDir = "${secretRoot}/zfs";
  aiSecretDir = "${secretRoot}/ai";
  observabilitySecretDir = "${secretRoot}/observability";
  powerSecretDir = "${secretRoot}/power";
  zfsKeyPath = "${zfsSecretDir}/dataset-key";
  zfsKeyFingerprintProperty = "org.nixos:keystore-sha256";
  vaultwardenBackupDir = "/var/backup/vaultwarden";
  caddyInternalCaPath = "/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt";
  caddyCaExportDir = "/run/nas-caddy-ca";
  caddyCaExportPath = "${caddyCaExportDir}/ca-bundle.crt";
  vaultwardenOidcClientId = "vaultwarden";
  vaultwardenOidcAuthority = "https://${lanHost}${cfg.identity.authentikPath}application/o/vaultwarden/";
  vaultwardenOidcCallback = "https://${lanHost}/vault/identity/connect/oidc-signin";
  shareRoot = "${cfg.zfsRoot}/shares";
  aiStorageRoot = if cfg.ai.storageRoot != "" then cfg.ai.storageRoot else "${cfg.zfsRoot}/ai";
  copypartyMountRoot = "/var/lib/copyparty/shares";
  tftpMountRoot = "${copypartyMountRoot}/tftp";
  vmStoragePath = if cfg.virtualization.storagePath != "" then cfg.virtualization.storagePath else "${cfg.zfsRoot}/virtual-machines";
  upsUsesLocalDriver = lib.elem cfg.power.ups.mode [ "standalone" "netserver" ];
  upsMonitorSystem =
    if cfg.power.ups.monitorSystem != "" then cfg.power.ups.monitorSystem
    else if upsUsesLocalDriver then "${cfg.power.ups.name}@localhost"
    else cfg.power.ups.name;
  syncthingDataDir = "/var/lib/syncthing";
  syncthingConfigDir = "${syncthingDataDir}/.config/syncthing";
  hostSystem = pkgs.stdenv.hostPlatform.system;
  isX86_64 = hostSystem == "x86_64-linux";
  supportedHostSystems = [ "x86_64-linux" ];
  failureAlert = lib.optional cfg.alerting.enable "nas-health-alert@%n";
  bootLoaderConfigured = config.boot.loader.systemd-boot.enable || config.boot.loader.grub.enable;
  rootFilesystem = lib.attrByPath [ "/" ] null config.fileSystems;
  rootFilesystemConfigured = rootFilesystem != null && (rootFilesystem.device or "") != "";

  caddyBackendUnits = [
    "authentik.service"
    "authentik-worker.service"
    "copyparty.service"
    "nas-on-demand-gate.service"
    "cockpit.socket"
  ];

  protectedServiceUnits = [
    "nas-zfs-mount-guard.service"
    "postgresql.service"
    "authentik-migrate.service"
    "authentik-worker.service"
    "authentik.service"
    "nas-identity-sync.service"
    "copyparty.service"
    "nas-on-demand-gate.service"
    "caddy.service"
  ] ++ lib.optional cfg.zfsEncryption.enable "nas-zfs-unlock.service";

  adminAccount = lib.attrByPath [ cfg.adminUser ] null config.users.users;
  adminGroups = if adminAccount == null then [ ] else (adminAccount.extraGroups or [ ]);
  adminKeys = if adminAccount == null then [ ] else lib.attrByPath [ "openssh" "authorizedKeys" "keys" ] [ ] adminAccount;
  observabilityUidCollisions = lib.attrNames (lib.filterAttrs
    (name: user: name != "nas-observability" && (user.uid or null) == cfg.observability.serviceUid)
    config.users.users);
  observabilityGidCollisions = lib.attrNames (lib.filterAttrs
    (name: group: name != "nas-observability" && (group.gid or null) == cfg.observability.serviceGid)
    config.users.groups);
  managementPorts =
    lib.optional cfg.observability.enable cfg.observability.victoriaMetricsPort
    ++ lib.optional (cfg.observability.enable && cfg.alerting.enable) cfg.observability.vmalertPort
    ++ lib.optional (cfg.observability.enable && cfg.alerting.enable) cfg.observability.alertRouterPort
    ++ lib.optional (cfg.observability.enable && cfg.observability.grafana.enable) cfg.observability.grafana.port
    ++ lib.optional (cfg.observability.ntfy.enable) cfg.observability.ntfy.port
    ++ lib.optional (cfg.power.ups.enable && cfg.power.ups.web.enable) cfg.power.ups.web.port;
  loopbackServicePorts = [
    authentikPort
    cockpitPort
  ]
  ++ lib.optional cfg.syncthing.enable syncthingGuiPort
  ++ lib.optional cfg.vaultwarden.enable vaultwardenPort
  ++ managementPorts
  ++ lib.optionals cfg.ai.enable [ cfg.ai.llamaSwap.port cfg.ai.openWebuiPort ]
  ++ lib.optional (cfg.ai.enable && cfg.ai.modelDownloader.enable) cfg.ai.modelDownloader.port;

  gpuVendors = cfg.hardware.gpuVendors;
  hasIntelGpu = lib.elem "intel" gpuVendors;
  hasAmdGpu = lib.elem "amd" gpuVendors;
  hasNvidiaGpu = lib.elem "nvidia" gpuVendors;
  llamaBackend = cfg.hardware.llamaCpp.backend;
  llamaCppPackage =
    if llamaBackend == "cuda" then pkgs.llama-cpp.override { cudaSupport = true; }
    else if llamaBackend == "rocm" then pkgs.llama-cpp.override { rocmSupport = true; }
    else if llamaBackend == "vulkan" then pkgs.llama-cpp.override { vulkanSupport = true; }
    else pkgs.llama-cpp;


in
{
  inherit
    cfg serviceRegistry lanHost identityAdminGroup secretRoot authentikSecretDir authentikEnvironmentFile
    authentikApiTokenFile authentikBootstrapTokenFile copypartyUserConfigDir
    featureCatalogPath featureSchemaPath featureStatePath featureRuntimePath onDemandGateSocket
    authentikPort cockpitPort syncthingGuiPort vaultwardenPort
    vaultwardenSecretDir zfsSecretDir aiSecretDir observabilitySecretDir powerSecretDir
    zfsKeyPath zfsKeyFingerprintProperty vaultwardenBackupDir caddyInternalCaPath
    caddyCaExportDir caddyCaExportPath vaultwardenOidcClientId vaultwardenOidcAuthority
    vaultwardenOidcCallback shareRoot aiStorageRoot copypartyMountRoot tftpMountRoot
    vmStoragePath upsUsesLocalDriver upsMonitorSystem syncthingDataDir syncthingConfigDir
    hostSystem isX86_64 supportedHostSystems failureAlert
    bootLoaderConfigured rootFilesystemConfigured caddyBackendUnits protectedServiceUnits adminAccount adminGroups
    adminKeys observabilityUidCollisions observabilityGidCollisions managementPorts
    loopbackServicePorts gpuVendors hasIntelGpu hasAmdGpu hasNvidiaGpu llamaBackend
    llamaCppPackage
  ;
}
