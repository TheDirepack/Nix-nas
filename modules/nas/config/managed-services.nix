{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikPort
    cfg
    identityAdminGroup
    lanHost
    nasPythonApplication
    onDemandGateSocket
  ;
  firewallEnabled = cfg.networking.enable && cfg.networking.firewall.enable;
  initialStore = pkgs.writeText "nas-managed-services-initial.json" ''{"schemaVersion":2,"generation":1,"services":{}}'';
  managedAppsCockpitPlugin = pkgs.runCommand "cockpit-nas-applications" { } ''
    install -d "$out/share/cockpit/nas-applications"
    cp ${../../../cockpit-managed-services/manifest.json} "$out/share/cockpit/nas-applications/manifest.json"
    cp ${../../../cockpit-managed-services/index.html} "$out/share/cockpit/nas-applications/index.html"
    cp ${../../../cockpit-managed-services/app.js} "$out/share/cockpit/nas-applications/app.js"
    cp ${../../../cockpit-managed-services/app.css} "$out/share/cockpit/nas-applications/app.css"
  '';
  managedService = pkgs.writeShellApplication {
    name = "nas-managed-service";
    runtimeInputs = [
      pkgs.caddy
      pkgs.coreutils
      pkgs.podman
      pkgs.podman-compose
      pkgs.systemd
    ]
    ++ lib.optional cfg.virtualization.enable pkgs.libvirt
    ++ lib.optional firewallEnabled config.services.firewalld.package;
    text = ''
      export NAS_MANAGED_SERVICE_SCHEMA=/etc/nas-control/managed-service.schema.json
      export NAS_BUILTIN_REGISTRY=/etc/nas-control/endpoints.json
      export NAS_MANAGED_SERVICE_STORE=/var/lib/nas-control/services.json
      export NAS_MANAGED_APP_ROOT=/var/lib/nas-control/apps
      export NAS_EFFECTIVE_REGISTRY=/run/nas-control/effective-endpoints.json
      export NAS_PORTAL_JSON=/run/nas-control/portal.json
      export NAS_CADDY_MANAGED_PATHS=/run/nas-control/caddy-managed-paths.caddy
      export NAS_CADDY_MANAGED_HOSTS=/run/nas-control/caddy-managed-hosts.caddy
      export NAS_MANAGED_FIREWALL_STATE=/var/lib/nas-firewall/managed-services.json
      export NAS_MANAGED_FIREWALL_ROOT=/var/lib/nas-firewall/firewalld
      export NAS_MANAGED_FIREWALL_REQUIRED=${if firewallEnabled then "1" else "0"}
      export NAS_CADDY_CONFIG=/etc/caddy/caddy_config
      export NAS_LAN_HOST=${lib.escapeShellArg lanHost}
      export NAS_AUTHENTIK_PORT=${toString authentikPort}
      export NAS_AUTHENTIK_PATH=${lib.escapeShellArg cfg.identity.authentikPath}
      export NAS_IDENTITY_ADMIN_GROUP=${lib.escapeShellArg identityAdminGroup}
      export NAS_ON_DEMAND_SOCKET=${lib.escapeShellArg onDemandGateSocket}
      export NAS_MANAGED_FIREWALL_ZONE=${lib.escapeShellArg cfg.networking.firewall.zone}
      export PODMAN_COMPOSE_PROVIDER=${lib.escapeShellArg "${pkgs.podman-compose}/bin/podman-compose"}
      export PODMAN_COMPOSE_WARNING_LOGS=false
      exec ${nasPythonApplication}/bin/nas-managed-service "$@"
    '';
  };
in
{
  config = {
    environment.etc."nas-control/managed-service.schema.json".source = ../../../schemas/managed-service.schema.json;
    environment.systemPackages = [ managedService pkgs.podman-compose ];
    services.cockpit.plugins = lib.mkAfter [ managedAppsCockpitPlugin ];

    systemd.tmpfiles.rules = [
      "d /var/lib/nas-control/apps 0700 root root -"
      "C /var/lib/nas-control/services.json 0600 nas-feature-gate nas-feature-control - ${initialStore}"
      "d /run/nas-control 0755 root root -"
      "f /run/nas-control/effective-endpoints.json 0644 root root -"
      "f /run/nas-control/portal.json 0644 root root -"
      "f /run/nas-control/caddy-managed-paths.caddy 0644 root root -"
      "f /run/nas-control/caddy-managed-hosts.caddy 0644 root root -"
    ] ++ lib.optionals firewallEnabled [
      "d /var/lib/nas-firewall/firewalld/zones 0700 root root -"
      "d /var/lib/nas-firewall/firewalld/policies 0700 root root -"
    ];

    # Caddy's generated config lives at /etc/caddy/caddy_config. Imports are
    # relative to that file, so ../../run resolves to the runtime projection.
    services.caddy.extraConfig = lib.mkAfter ''
      import ../../run/nas-control/caddy-managed-hosts.caddy
    '';
    services.caddy.virtualHosts.${lanHost}.extraConfig = lib.mkBefore ''
      import ../../run/nas-control/caddy-managed-paths.caddy
    '';

    systemd.services.nas-managed-services-reconcile = {
      description = "Reconcile NAS-managed containers, Compose projects, VMs, routes, firewall policy, and portal";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ]
        ++ lib.optionals firewallEnabled [ "firewalld.service" "nas-firewall-baseline.service" ]
        ++ lib.optional cfg.virtualization.enable "libvirtd.service";
      before = [ "caddy.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = false;
        ExecStart = "${managedService}/bin/nas-managed-service reconcile";
        UMask = "0077";
      };
    };

    systemd.paths.nas-managed-services-reconcile = {
      description = "Watch authoritative NAS managed-service configuration";
      wantedBy = [ "multi-user.target" ];
      pathConfig = {
        PathChanged = "/var/lib/nas-control/services.json";
        Unit = "nas-managed-services-reconcile.service";
      };
    };
  };
}
