{ config, lib, pkgs, aiInternal, ... }:

let
  inherit (aiInternal)
    aiRoot
    aiSecretDir
    backendCache
    cfg
    defaultConfig
    legacyDefaultConfig
    hfRoot
    legacyStateDir
    nas
    secretRoot
    stateDir
  ;
in
{
  config = lib.mkIf cfg.enable {
    systemd.services = {
      nas-ai-storage = {
        wantedBy = lib.mkOverride 90 [ ];
        description = "Prepare ZFS-backed local AI storage";
        requires = [ "nas-zfs-mount-guard.service" ];
        after = [ "nas-zfs-mount-guard.service" ];
        before = [
          "nas-ai-config-init.service"
          "nas-llama-swap.service"
          "open-webui.service"
        ] ++ lib.optional cfg.modelDownloader.enable "podman-hfdownloader.service";
        partOf = [ "nas-protected-services.target" ];
        unitConfig.ConditionPathExists = "${secretRoot}/ready";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          User = "root";
          Group = "root";
        };
        script = ''
          set -euo pipefail
          ${pkgs.util-linux}/bin/mountpoint -q ${lib.escapeShellArg nas.zfsRoot}
          install -d -m 2770 -o hfdownloader -g nas-ai-models \
            ${lib.escapeShellArg aiRoot} \
            ${lib.escapeShellArg hfRoot} \
            ${lib.escapeShellArg "${hfRoot}/hub"} \
            ${lib.escapeShellArg "${hfRoot}/models"} \
            ${lib.escapeShellArg "${aiRoot}/downloader-config"} \
            ${lib.escapeShellArg backendCache}
          # Avoid recursive ownership changes on the model cache.
          chown hfdownloader:nas-ai-models \
            ${lib.escapeShellArg hfRoot} ${lib.escapeShellArg "${aiRoot}/downloader-config"}
          chmod 2770 ${lib.escapeShellArg hfRoot} ${lib.escapeShellArg "${aiRoot}/downloader-config"}
        '';
      };

      nas-ai-config-init = {
        wantedBy = lib.mkOverride 90 [ ];
        description = "Seed the writable llama-swap configuration";
        requires = [ "nas-ai-storage.service" ];
        after = [ "nas-ai-storage.service" ];
        before = [ "nas-llama-swap.service" ];
        partOf = [ "nas-protected-services.target" ];
        unitConfig.ConditionPathExists = "${secretRoot}/ready";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          User = "root";
          Group = "root";
          StateDirectory = "nas-llama-swap";
          StateDirectoryMode = "0750";
          UMask = "0007";
        };
        script = ''
          set -euo pipefail
          install -d -m 0750 -o nas-ai -g nas-ai ${lib.escapeShellArg stateDir}
          if [[ ! -e ${lib.escapeShellArg "${stateDir}/config.yaml"} ]]; then
            if [[ -e ${lib.escapeShellArg "${legacyStateDir}/llama-swap.json"} ]]; then
              install -m 0640 -o nas-ai -g nas-ai \
                ${lib.escapeShellArg "${legacyStateDir}/llama-swap.json"} \
                ${lib.escapeShellArg "${stateDir}/config.yaml"}
            else
              install -m 0640 -o nas-ai -g nas-ai \
                ${defaultConfig} ${lib.escapeShellArg "${stateDir}/config.yaml"}
            fi
          elif cmp -s ${legacyDefaultConfig} ${lib.escapeShellArg "${stateDir}/config.yaml"}; then
            # Migrate only the untouched prior default; never rewrite administrator-owned
            # llama-swap configuration just to add the coding-agent client credential.
            install -m 0640 -o nas-ai -g nas-ai \
              ${defaultConfig} ${lib.escapeShellArg "${stateDir}/config.yaml"}
          fi
        '';
      };

      nas-llama-swap = {
        description = "Backend-neutral local AI control plane";
        requires = [ "nas-ai-config-init.service" ];
        after = [ "nas-ai-config-init.service" ];
        partOf = [ "nas-protected-services.target" ];
        wantedBy = lib.mkOverride 90 [ ];
        unitConfig.ConditionPathExists = [ "${secretRoot}/ready" "${aiSecretDir}/llama-swap.env" ];
        environment = {
          HOME = stateDir;
          LLAMA_CACHE = backendCache;
        };
        serviceConfig = {
          Type = "exec";
          User = "nas-ai";
          Group = "nas-ai";
          EnvironmentFile = "${aiSecretDir}/llama-swap.env";
          StateDirectory = "nas-llama-swap";
          StateDirectoryMode = "0750";
          UMask = "0007";
          ExecStart = "${lib.getExe pkgs.llama-swap} --listen=127.0.0.1:${toString cfg.llamaSwap.port} --config=${stateDir}/config.yaml --watch-config";
          Restart = "on-failure";
          RestartSec = "3s";
          KillSignal = "SIGINT";
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          ReadWritePaths = [ stateDir backendCache ];
          PrivateDevices = false;
          RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        };
      };

      open-webui = {
        wantedBy = lib.mkOverride 90 [ ];
        requires = lib.mkAfter [ "nas-ai-storage.service" ];
        after = lib.mkAfter [ "nas-ai-storage.service" "nas-llama-swap.service" ];
        partOf = lib.mkAfter [ "nas-protected-services.target" ];
        unitConfig.ConditionPathExists = lib.mkOverride 90 [ "${secretRoot}/ready" "${aiSecretDir}/open-webui.env" ];
      };

      podman-hfdownloader = lib.mkIf cfg.modelDownloader.enable {
        wantedBy = lib.mkOverride 90 [ ];
        requires = lib.mkAfter [ "nas-ai-storage.service" ];
        after = lib.mkAfter [ "nas-ai-storage.service" ];
        partOf = lib.mkAfter [ "nas-protected-services.target" ];
        unitConfig.ConditionPathExists = lib.mkOverride 90 [ "${secretRoot}/ready" "${aiSecretDir}/hfdownloader.env" ];
      };
    };
  };
}
