{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cfg
    cockpitPort
  ;
  zone = cfg.networking.firewall.zone;
  firewallCmd = "${config.services.firewalld.package}/bin/firewall-cmd";
  nmcli = "${pkgs.networkmanager}/bin/nmcli";
  firewalldStateRoot = "/var/lib/nas-firewall/firewalld";
  firewalldSeedConfig = pkgs.writeText "nas-firewalld.conf" ''
    DefaultZone=drop
    CleanupOnExit=yes
    CleanupModulesOnExit=no
    FirewallBackend=nftables
    FlushAllOnReload=yes
    LogDenied=off
    NftablesTableOwner=yes
  '';
  trustedInterfacesArgs = lib.concatMapStringsSep " " lib.escapeShellArg cfg.trustedInterfaces;
  ownedServices = [ "ssh" "http" "https" "mdns" ];
  ownedPorts = [
    { port = "443"; protocol = "udp"; }
  ]
  ++ lib.optional cfg.hostPolicy.directCockpitRecovery {
    port = toString cockpitPort;
    protocol = "tcp";
  }
  ++ lib.optionals cfg.syncthing.enable [
    { port = "22000"; protocol = "tcp"; }
    { port = "22000"; protocol = "udp"; }
    { port = "21027"; protocol = "udp"; }
  ]
  ++ lib.optional (cfg.power.ups.enable && cfg.power.ups.mode == "netserver") {
    port = "3493";
    protocol = "tcp";
  }
  ++ lib.optionals cfg.tftp.enable [
    {
      port = "${toString cfg.tftp.responsePortStart}-${toString cfg.tftp.responsePortEnd}";
      protocol = "udp";
    }
  ]
  ++ lib.optional (cfg.tftp.enable && cfg.tftp.port == cfg.tftp.internalPort) {
    port = toString cfg.tftp.port;
    protocol = "udp";
  };
  ownedForwardPorts = lib.optional (cfg.tftp.enable && cfg.tftp.port != cfg.tftp.internalPort) {
    port = toString cfg.tftp.port;
    protocol = "udp";
    toPort = toString cfg.tftp.internalPort;
  };
  zoneXml = pkgs.writeText "nas-owned-zone.xml" ''
    <zone target="default">
      <short>NixOS NAS trusted management</short>
      <description>Exact NixOS NAS owned rule set. Local mutable additions belong in a separate zone.</description>
      ${lib.concatMapStringsSep "\n" (service: ''<service name="${service}"/>'') ownedServices}
      ${lib.concatMapStringsSep "\n" (entry: ''<port port="${entry.port}" protocol="${entry.protocol}"/>'') ownedPorts}
      ${lib.concatMapStringsSep "\n" (entry: ''<forward-port port="${entry.port}" protocol="${entry.protocol}" to-port="${entry.toPort}"/>'') ownedForwardPorts}
    </zone>
  '';
  requiredRuleChecks = lib.concatStringsSep "\n" (
    (map (service: ''
      ${firewallCmd} --zone=${lib.escapeShellArg zone} --query-service=${lib.escapeShellArg service} >/dev/null || {
        echo "Required service ${service} is missing from ${zone}." >&2
        exit 1
      }
    '') ownedServices)
    ++ (map (entry: ''
      ${firewallCmd} --zone=${lib.escapeShellArg zone} --query-port=${lib.escapeShellArg "${entry.port}/${entry.protocol}"} >/dev/null || {
        echo "Required port ${entry.port}/${entry.protocol} is missing from ${zone}." >&2
        exit 1
      }
    '') ownedPorts)
    ++ (map (entry: ''
      ${firewallCmd} --zone=${lib.escapeShellArg zone} --query-forward-port=${lib.escapeShellArg "port=${entry.port}:proto=${entry.protocol}:toport=${entry.toPort}"} >/dev/null || {
        echo "Required forward port ${entry.port}/${entry.protocol} is missing from ${zone}." >&2
        exit 1
      }
    '') ownedForwardPorts)
  );
  staleRuleChecks = lib.concatStringsSep "\n" (
    (map (service: ''
      if ${firewallCmd} --zone="$other_zone" --query-service=${lib.escapeShellArg service} >/dev/null 2>&1; then
        echo "NAS-owned service ${service} is unexpectedly exposed in zone $other_zone." >&2
        exit 1
      fi
    '') ownedServices)
    ++ (map (entry: ''
      if ${firewallCmd} --zone="$other_zone" --query-port=${lib.escapeShellArg "${entry.port}/${entry.protocol}"} >/dev/null 2>&1; then
        echo "NAS-owned port ${entry.port}/${entry.protocol} is unexpectedly exposed in zone $other_zone." >&2
        exit 1
      fi
    '') ownedPorts)
    ++ (map (entry: ''
      if ${firewallCmd} --zone="$other_zone" --query-forward-port=${lib.escapeShellArg "port=${entry.port}:proto=${entry.protocol}:toport=${entry.toPort}"} >/dev/null 2>&1; then
        echo "NAS-owned forward port ${entry.port}/${entry.protocol} is unexpectedly exposed in zone $other_zone." >&2
        exit 1
      fi
    '') ownedForwardPorts)
  );
in
{
  config = lib.mkIf cfg.networking.enable {
    networking.networkmanager = {
      enable = true;
      dns = "systemd-resolved";
    };
    services.resolved.enable = true;

    services.firewalld = lib.mkIf cfg.networking.firewall.enable {
      enable = true;
      extraArgs = [ "--system-config=${firewalldStateRoot}" ];
      settings = {
        DefaultZone = "drop";
        FirewallBackend = "nftables";
        NftablesTableOwner = true;
        CleanupOnExit = true;
        FlushAllOnReload = true;
        LogDenied = "off";
      };
    };
    networking.firewall = lib.mkIf cfg.networking.firewall.enable {
      enable = true;
      backend = "firewalld";
      allowedTCPPorts = [ ];
      allowedUDPPorts = [ ];
      interfaces = { };
    };

    systemd.services.firewalld = lib.mkIf cfg.networking.firewall.enable {
      restartTriggers = [ firewalldSeedConfig zoneXml ];
      serviceConfig = {
        StateDirectory = "nas-firewall";
        StateDirectoryMode = "0700";
      };
      preStart = ''
        ${pkgs.coreutils}/bin/install -d -m 0700 ${firewalldStateRoot} ${firewalldStateRoot}/zones
        ${pkgs.coreutils}/bin/install -m 0600 ${firewalldSeedConfig} ${firewalldStateRoot}/firewalld.conf
        ${pkgs.coreutils}/bin/install -m 0600 ${zoneXml} ${firewalldStateRoot}/zones/${zone}.xml
        ${pkgs.coreutils}/bin/find ${firewalldStateRoot}/zones -maxdepth 1 -type f \
          -name '${zone}.xml.old' -delete
      '';
    };

    systemd.services.nas-firewall-baseline = lib.mkIf (
      cfg.networking.firewall.enable
      && cfg.networking.firewall.seedDefaults
      && cfg.trustedInterfaces != [ ]
    ) {
      description = "Reconcile the exact NetworkManager and firewalld NAS baseline";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      requires = [ "NetworkManager.service" "firewalld.service" ];
      after = [ "NetworkManager.service" "firewalld.service" "network-online.target" ];
      restartTriggers = [ zoneXml ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "nas-firewall";
        UMask = "0077";
      };
      path = [ pkgs.coreutils pkgs.gnugrep pkgs.networkmanager config.services.firewalld.package ];
      script = ''
        set -euo pipefail
        missing_profile=false

        # The complete zone file is installed before firewalld starts. Never add
        # NAS rules to an interface's previous/default zone as a bootstrap shortcut.
        ${firewallCmd} --check-config
        ${firewallCmd} --reload

        for interface in ${trustedInterfacesArgs}; do
          connection="$(${nmcli} -g GENERAL.CONNECTION device show "$interface" 2>/dev/null | head -n1 || true)"
          if [[ -n "$connection" && "$connection" != "--" ]]; then
            ${nmcli} connection modify "$connection" connection.zone ${lib.escapeShellArg zone}
            ${nmcli} device reapply "$interface" >/dev/null
            ${firewallCmd} --zone=${lib.escapeShellArg zone} --change-interface="$interface"
          else
            echo "No NetworkManager connection profile exists for $interface; refusing to open management services." >&2
            missing_profile=true
          fi
        done

        if $missing_profile; then
          exit 1
        fi
      '';
    };

    systemd.services.nas-management-network-guard = lib.mkIf (
      cfg.hostPolicy.directCockpitRecovery
      && cfg.networking.firewall.enable
      && cfg.trustedInterfaces != [ ]
      && !cfg.testing.installationReadyFixture
    ) {
      description = "Verify exact trusted-interface firewall policy before management access";
      requiredBy = [ "cockpit.socket" ];
      before = [ "cockpit.socket" ];
      wants = [ "network-online.target" ];
      requires = [ "firewalld.service" "nas-firewall-baseline.service" ];
      after = [ "firewalld.service" "nas-firewall-baseline.service" "NetworkManager.service" "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      path = [ pkgs.coreutils pkgs.gnugrep pkgs.iproute2 pkgs.networkmanager config.services.firewalld.package ];
      script = ''
        set -euo pipefail
        for interface in ${trustedInterfacesArgs}; do
          ip link show "$interface" >/dev/null
          ip -o address show dev "$interface" scope global | grep -q . || {
            echo "Trusted interface $interface has no global address." >&2
            exit 1
          }
          connection="$(${nmcli} -g GENERAL.CONNECTION device show "$interface")"
          [[ -n "$connection" && "$connection" != "--" ]] || {
            echo "Trusted interface $interface has no active NetworkManager profile." >&2
            exit 1
          }
          configured_zone="$(${nmcli} -g connection.zone connection show "$connection")"
          [[ "$configured_zone" == ${lib.escapeShellArg zone} ]] || {
            echo "NetworkManager profile $connection persists zone $configured_zone instead of ${zone}." >&2
            exit 1
          }
          current_zone="$(${firewallCmd} --get-zone-of-interface="$interface")"
          [[ "$current_zone" == ${lib.escapeShellArg zone} ]] || {
            echo "Trusted interface $interface is assigned to $current_zone instead of ${zone}." >&2
            exit 1
          }
        done

        ${requiredRuleChecks}
        while IFS= read -r other_zone; do
          [[ -n "$other_zone" && "$other_zone" != ${lib.escapeShellArg zone} ]] || continue
          ${staleRuleChecks}
        done < <(${firewallCmd} --get-active-zones | ${pkgs.gawk}/bin/awk '/^[^[:space:]]/ { print $1 }')
      '';
    };
  };
}
