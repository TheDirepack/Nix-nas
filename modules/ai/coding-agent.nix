{ config, lib, pkgs, aiInternal, nasInternal, ... }:

let
  inherit (aiInternal) aiSecretDir cfg;
  inherit (nasInternal) nasPythonApplication;
  code = cfg.codingAgent;
  piPackageAvailable = builtins.hasAttr "pi-coding-agent" pkgs;
  piPackage = if piPackageAvailable then pkgs."pi-coding-agent" else null;
  stateDir = "/var/lib/nas-code-agent";
  piNetnsPath = "/run/netns/pi";
  piHostVethIp = "10.200.1.1";
  piNsVethIp = "10.200.1.2";
  providerName = "nas-llama-swap";
  roleModels = lib.unique (builtins.attrValues code.modelRoles);
  modelsFile = pkgs.writeText "nas-pi-models.json" (builtins.toJSON {
    providers.${providerName} = {
      baseUrl = "http://${piHostVethIp}:${toString cfg.llamaSwap.port}/v1";
      apiKey = "LLAMA_SWAP_CODING_API_KEY";
      api = "openai-completions";
      models = map (id: {
        inherit id;
        name = id;
        reasoning = false;
        input = [ "text" ];
        cost = { input = 0; output = 0; cacheRead = 0; cacheWrite = 0; };
        contextWindow = code.contextWindow;
        maxTokens = code.maxTokens;
        compat = { supportsDeveloperRole = false; };
      }) roleModels;
    };
  });
  settingsFile = pkgs.writeText "nas-pi-settings.json" (builtins.toJSON {
    defaultProvider = providerName;
    defaultModel = code.modelRoles.default;
  });
  piConfigDir = pkgs.runCommand "nas-pi-agent-config" { } ''
    mkdir -p "$out"
    cp ${modelsFile} "$out/models.json"
    cp ${settingsFile} "$out/settings.json"
  '';
  piExecutable = if piPackageAvailable then "${piPackage}/bin/pi" else "${pkgs.coreutils}/bin/false";
  sessionExec = pkgs.writeShellScript "nas-pi-session" ''
    set -euo pipefail
    : "''${CREDENTIALS_DIRECTORY:?systemd credential directory is unavailable}"
    key_file="$CREDENTIALS_DIRECTORY/llama-swap-api-key"
    [[ -r "$key_file" ]] || { echo "Pi llama-swap credential is unavailable" >&2; exit 1; }
    LLAMA_SWAP_CODING_API_KEY="$(cat "$key_file")"
    export LLAMA_SWAP_CODING_API_KEY
    export PI_CODING_AGENT_DIR=${lib.escapeShellArg (toString piConfigDir)}
    export PI_CODING_AGENT_SESSION_DIR=${lib.escapeShellArg "${stateDir}/sessions"}
    export PI_PACKAGE_DIR=${lib.escapeShellArg "${stateDir}/packages"}
    export PI_OFFLINE=1
    export PI_SKIP_VERSION_CHECK=1
    export PI_TELEMETRY=0
    exec ${piExecutable} --no-extensions --no-skills --no-prompt-templates --no-themes --no-context-files "$@"
  '';
  launcher = pkgs.writeShellApplication {
    name = "nas-code";
    runtimeInputs = [ nasPythonApplication pkgs.systemd ];
    text = ''
      export NAS_CODING_WORKSPACE_ROOTS_JSON=${lib.escapeShellArg (builtins.toJSON code.workspaceRoots)}
      export NAS_PI_SESSION_EXEC=${lib.escapeShellArg sessionExec}
      export NAS_PI_CREDENTIAL=${lib.escapeShellArg "${aiSecretDir}/coding-agent-api-key"}
      export NAS_PI_STATE_DIR=${lib.escapeShellArg stateDir}
      export NAS_MANAGED_SERVICES_CONTROL=${lib.escapeShellArg "${nasPythonApplication}/bin/nas-managed-services-control"}
      export NAS_CODING_HEARTBEAT_SECONDS=${toString code.heartbeatSeconds}
      exec ${nasPythonApplication}/bin/nas-code-agent "$@"
    '';
  };
in
{
  config = lib.mkMerge [
    {
      assertions = lib.optional (cfg.enable && code.enable) {
        assertion = piPackageAvailable;
        message = "nas.ai.codingAgent.enable requires nixpkgs to provide pkgs.pi-coding-agent.";
      };
    }
    (lib.mkIf (cfg.enable && code.enable && piPackageAvailable) {
      # The caller must supply the already-authenticated identity. Authorization
      # itself is the canonical application.ai-coding.access Authentik assignment;
      # no Linux-group or UID fallback is retained.
      security.sudo.extraConfig = ''
        Defaults env_keep += "NAS_AUTHENTICATED_IDENTITY_JSON"
      '';

      environment.etc."systemd/resolved.conf.d/10-pi-netns.conf".text = ''
        [Resolve]
        DNSStubListenerExtra=${piHostVethIp}
      '';

      environment.systemPackages = [ piPackage launcher ];

      systemd.slices.nas-ai-coding = {
        description = "Pi coding-agent session slice";
        wantedBy = lib.mkOverride 90 [ ];
        partOf = [ "nas-protected-services.target" ];
        unitConfig.Before = [ "nas-ai-coding-sessions.target" ];
      };

      systemd.targets.nas-ai-coding-sessions = {
        description = "Active Pi coding-agent sessions";
        wantedBy = lib.mkOverride 90 [ ];
        partOf = [ "nas-protected-services.target" ];
        requires = [ "nas-ai-coding-prepare.service" "nas-pi-netns.service" "nas-llama-swap-pi-proxy.service" ];
        after = [ "nas-ai-coding-prepare.service" "nas-pi-netns.service" "nas-llama-swap-pi-proxy.service" ];
        # Managed Services V2 adds StopWhenUnneeded=yes in its owned drop-in for
        # the on-demand ai-coding service and refreshes its native lease while a
        # transient session is active.
        unitConfig.StopWhenUnneeded = false;
      };

      systemd.services.nas-pi-netns = {
        description = "Create Pi coding-agent network namespace (internet via NAT, host loopback blocked except llama-swap proxy)";
        wantedBy = lib.mkOverride 90 [ "nas-ai-coding-sessions.target" ];
        before = [ "nas-ai-coding-sessions.target" ];
        partOf = [ "nas-protected-services.target" ];
        after = [ "nas-ai-storage.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = pkgs.writeShellScript "nas-pi-netns-setup" ''
            set -euo pipefail
            ${pkgs.iproute2}/bin/ip netns add pi 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip link add pi-veth0 type veth peer name pi-veth1 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip link set pi-veth1 netns pi 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip addr add ${piHostVethIp}/30 dev pi-veth0 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip link set pi-veth0 up 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip netns exec pi ${pkgs.iproute2}/bin/ip addr add ${piNsVethIp}/30 dev pi-veth1 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip netns exec pi ${pkgs.iproute2}/bin/ip link set pi-veth1 up 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip netns exec pi ${pkgs.iproute2}/bin/ip link set lo up 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip netns exec pi ${pkgs.iproute2}/bin/ip route add default via ${piHostVethIp} 2>/dev/null || true
            ${pkgs.iptables}/bin/iptables -t nat -C POSTROUTING -s ${piNsVethIp}/30 -j MASQUERADE 2>/dev/null || ${pkgs.iptables}/bin/iptables -t nat -A POSTROUTING -s ${piNsVethIp}/30 -j MASQUERADE
            ${pkgs.iptables}/bin/iptables -C FORWARD -s ${piNsVethIp}/30 -j ACCEPT 2>/dev/null || ${pkgs.iptables}/bin/iptables -A FORWARD -s ${piNsVethIp}/30 -j ACCEPT
            ${pkgs.iptables}/bin/iptables -C FORWARD -d ${piNsVethIp}/30 -j ACCEPT 2>/dev/null || ${pkgs.iptables}/bin/iptables -A FORWARD -d ${piNsVethIp}/30 -j ACCEPT
            mkdir -p /etc/netns/pi
            printf 'nameserver ${piHostVethIp}\n' > /etc/netns/pi/resolv.conf
          '';
          ExecStop = pkgs.writeShellScript "nas-pi-netns-teardown" ''
            set -euo pipefail
            ${pkgs.iptables}/bin/iptables -t nat -D POSTROUTING -s ${piNsVethIp}/30 -j MASQUERADE 2>/dev/null || true
            ${pkgs.iptables}/bin/iptables -D FORWARD -s ${piNsVethIp}/30 -j ACCEPT 2>/dev/null || true
            ${pkgs.iptables}/bin/iptables -D FORWARD -d ${piNsVethIp}/30 -j ACCEPT 2>/dev/null || true
            rm -f /etc/netns/pi/resolv.conf
            rmdir /etc/netns/pi 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip netns del pi 2>/dev/null || true
            ${pkgs.iproute2}/bin/ip link del pi-veth0 2>/dev/null || true
          '';
        };
      };

      systemd.services.nas-llama-swap-pi-proxy = {
        description = "Proxy host llama-swap to Pi netns (10.200.1.1:${toString cfg.llamaSwap.port} -> 127.0.0.1:${toString cfg.llamaSwap.port})";
        wantedBy = lib.mkOverride 90 [ "nas-ai-coding-sessions.target" ];
        after = [ "nas-pi-netns.service" "nas-llama-swap.service" ];
        partOf = [ "nas-protected-services.target" ];
        requires = [ "nas-pi-netns.service" ];
        serviceConfig = {
          Type = "simple";
          Restart = "always";
          RestartSec = "2s";
          ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:${toString cfg.llamaSwap.port},fork,bind=${piHostVethIp},reuseaddr TCP:127.0.0.1:${toString cfg.llamaSwap.port}";
        };
      };

      systemd.services.nas-ai-coding-prepare = {
        description = "Prepare the transient Pi coding-agent runtime";
        requires = [ "nas-ai-storage.service" ];
        after = [ "nas-ai-storage.service" ];
        before = [ "nas-ai-coding-sessions.target" ];
        partOf = [ "nas-protected-services.target" ];
        wantedBy = lib.mkOverride 90 [ "nas-ai-coding-sessions.target" ];
        unitConfig.ConditionPathExists = [ "/run/nas-secrets/ready" "${aiSecretDir}/coding-agent-api-key" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          User = "root";
          Group = "root";
          StateDirectory = "nas-code-agent";
          StateDirectoryMode = "0750";
          UMask = "0007";
        };
        script = ''
          set -euo pipefail
          install -d -m 0750 -o nas-code-agent -g nas-code-agent ${lib.escapeShellArg stateDir}
          install -d -m 0700 -o nas-code-agent -g nas-code-agent \
            ${lib.escapeShellArg "${stateDir}/sessions"} ${lib.escapeShellArg "${stateDir}/packages"}
          ${lib.concatMapStringsSep "\n" (root: ''
            if [[ ! -e ${lib.escapeShellArg root} ]]; then
              install -d -m 2770 -o root -g nas-code-agent ${lib.escapeShellArg root}
            fi
            [[ -d ${lib.escapeShellArg root} && ! -L ${lib.escapeShellArg root} ]] || {
              echo "Coding workspace root must be a real directory: ${root}" >&2
              exit 1
            }
            if ! sudo -u nas-code-agent test -x ${lib.escapeShellArg root}; then
              echo "Coding workspace root is not traversable by nas-code-agent: ${root}" >&2
              echo "Fix with: chown :nas-code-agent ${root} && chmod 2770 ${root} or add ACL via setfacl -m g:nas-code-agent:rwx ${root}" >&2
              exit 1
            fi
            if ! sudo -u nas-code-agent test -w ${lib.escapeShellArg root}; then
              echo "Coding workspace root is not writable by nas-code-agent: ${root}" >&2
              echo "Fix with: chown :nas-code-agent ${root} && chmod 2770 ${root} or add ACL via setfacl -m g:nas-code-agent:rwx ${root}" >&2
              exit 1
            fi
            # Group/ACL-based filesystem access is distinct from application authorization.
          '') code.workspaceRoots}
        '';
      };
    })
  ];
}
