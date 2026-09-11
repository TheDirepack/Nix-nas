{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikOutpostPort
    authentikPort
    caddyForwardAuth
    cfg
    cockpitPort
    firstRunWizardStatic
    lanHost
    secretRoot
  ;
  authentikPathNoSlash = lib.removeSuffix "/" cfg.identity.authentikPath;
  activeCaddyPath = "/run/nas-control/caddy-active.conf";
  bootstrapCaddyfileGen = pkgs.writeShellScript "bootstrap-caddyfile-gen" ''
    cat <<EOCF
{
  log {
    output file ${config.services.caddy.logDir}/access.log {
      mode 0640
      roll_size 100MiB
      roll_keep 10
      roll_keep_for 720h
    }
    format json
  }
}

https://${lanHost} {
  tls internal
  encode zstd gzip
  header {
    -Server
    X-Content-Type-Options "nosniff"
    Referrer-Policy "no-referrer"
    Permissions-Policy "camera=(), microphone=(), geolocation=()"
  }

  handle / {
    redir * ${cfg.identity.authentikPath}if/user/ 303
  }
  # /setup without the slash would make the wizard's relative asset URLs
  # resolve against /, so canonicalise to /setup/ before serving.
  handle /setup {
    redir /setup /setup/ 308
  }
  # Rebuilding Authentik invalidates the temporary session while the detached
  # job is still running. Job status and completed-job reboot authenticate
  # with a server-issued header capability, never a job id in the URL, so the
  # capability never reaches proxy logs. Submission and resume stay
  # Authentik-gated through the route below.
  # The socket path must match nas-setup-api.service (application-services.nix).
  handle /setup/api/first-start/job {
    reverse_proxy unix//run/nas-setup-api/setup.sock
  }
  handle /setup/api/reboot {
    reverse_proxy unix//run/nas-setup-api/setup.sock
  }
  # The wizard's submission API. Authentik-gated like the page itself; the
  # socket path must match nas-setup-api.service (application-services.nix).
  handle /setup/api/* {
    route {
      ${caddyForwardAuth}
      reverse_proxy unix//run/nas-setup-api/setup.sock
    }
  }
  handle /setup/* {
    route {
      ${caddyForwardAuth}
      @post method POST
      handle @post {
        redir * /setup/ 303
      }
      uri strip_prefix /setup
      root * ${firstRunWizardStatic}/share/nas-portal-wizard
      file_server
    }
  }

  redir ${authentikPathNoSlash} ${cfg.identity.authentikPath}
  @authentikUi path ${cfg.identity.authentikPath}*
  handle @authentikUi {
    reverse_proxy 127.0.0.1:${toString authentikPort}
  }
  @authentikFlows path /flows/*
  handle @authentikFlows {
    uri replace /flows ${cfg.identity.authentikPath}flows
    reverse_proxy 127.0.0.1:${toString authentikPort}
  }
  @authentikOutpost path /outpost.goauthentik.io/*
  handle @authentikOutpost {
    reverse_proxy 127.0.0.1:${toString authentikOutpostPort} {
      header_up Host {http.request.host}
      header_up X-Forwarded-Proto https
    }
  }
  handle /console* {
    route {
      ${caddyForwardAuth}
      @missingCockpitAdmin not header_regexp Remote-Groups (?i)(^|[|,][[:space:]]*)nas_admin([[:space:]]*[|,]|$)
      respond @missingCockpitAdmin 403
      reverse_proxy 127.0.0.1:${toString cockpitPort} {
        header_up X-Forwarded-Proto https
        header_up X-Forwarded-Prefix /console
      }
    }
  }

  handle {
    redir * ${cfg.identity.authentikPath}if/user/ 303
  }
}
EOCF
  '';
  bootstrapCaddyfile = pkgs.runCommand "bootstrap-caddyfile" {
    nativeBuildInputs = [ bootstrapCaddyfileGen ];
  } ''
    ${bootstrapCaddyfileGen} > $out
  '';
  fullCaddyImport = "import /etc/caddy/caddy_config";
  caddyPackage = config.services.caddy.package;
  runOptions = "--config ${activeCaddyPath} --adapter caddyfile";
  managedPath = "/run/nas-control/caddy-managed.conf";
  planPath = "/run/nas-control/plan.json";
  desiredPath = "/var/lib/nas-control/services.yaml";
  authorityLockPath = "/var/lib/nas-control/.services.yaml.lock";
  historyRepoPath = "${cfg.zfsRoot}/nas-control/config-history.git";
  selectorLockPath = "/run/nas-control/caddy-bootstrap.lock";
  renderActive = pkgs.writeShellScript "nas-caddy-bootstrap-select" ''
    set -euo pipefail
    activeCaddyPath="${activeCaddyPath}"
    managedPath="${managedPath}"
    planPath="${planPath}"
    desiredPath="${desiredPath}"
    authorityLockPath="${authorityLockPath}"
    historyRepoPath="${historyRepoPath}"
    bootstrapImport="import ${bootstrapCaddyfile}"
    fullImport=${lib.escapeShellArg fullCaddyImport}

    exec 9>${lib.escapeShellArg selectorLockPath}
    ${pkgs.util-linux}/bin/flock -x 9

    write_active() {
      local content="$1"
      local tmp
      tmp="$(${pkgs.coreutils}/bin/mktemp "$activeCaddyPath.XXXXXX")"
      if ! ${pkgs.coreutils}/bin/printf '%s\n' "$content" > "$tmp" \
        || ! ${pkgs.coreutils}/bin/chmod 0644 "$tmp" \
        || ! ${pkgs.coreutils}/bin/mv -f "$tmp" "$activeCaddyPath"; then
        ${pkgs.coreutils}/bin/rm -f "$tmp"
        return 1
      fi
    }
    select_bootstrap() {
      write_active "$bootstrapImport"
    }
    select_full() {
      write_active "$fullImport"
    }
    reload_caddy() {
      ${caddyPackage}/bin/caddy reload ${runOptions} --force
    }
    reload_bootstrap() {
      select_bootstrap
      if ${pkgs.systemd}/bin/systemctl is-active --quiet caddy.service; then
        if ! reload_caddy; then
          ${pkgs.systemd}/bin/systemctl stop --no-block caddy.service
          return 1
        fi
      fi
    }
    generated_is_current() {
      [[ -f "$managedPath" && -f "$planPath" && -f "$desiredPath" ]] || return 1
      local desired_revision head_revision applied_revision
      desired_revision="$(${pkgs.jq}/bin/jq -er \
        '.desiredRevision | select(type == "string" and test("^[0-9a-f]{40}$"))' \
        "$planPath" 2>/dev/null)" || return 1
      head_revision="$(${pkgs.git}/bin/git --git-dir="$historyRepoPath" \
        --work-tree="$(${pkgs.coreutils}/bin/dirname "$desiredPath")" \
        rev-parse --verify HEAD 2>/dev/null)" || return 1
      applied_revision="$(${pkgs.git}/bin/git --git-dir="$historyRepoPath" \
        rev-parse --verify refs/nas/applied 2>/dev/null)" || return 1
      [[ "$desired_revision" == "$head_revision" && "$desired_revision" == "$applied_revision" ]] || return 1
      ${pkgs.git}/bin/git --git-dir="$historyRepoPath" \
        --work-tree="$(${pkgs.coreutils}/bin/dirname "$desiredPath")" \
        diff --quiet "$desired_revision" -- "$(${pkgs.coreutils}/bin/basename "$desiredPath")"
    }
    managed_is_valid() {
      [[ -f "$managedPath" ]] || return 1
      local validation_root tmp status
      validation_root="$(${pkgs.coreutils}/bin/mktemp -d)"
      tmp="$validation_root/Caddyfile"
      if ! ${pkgs.coreutils}/bin/mkdir -p "$validation_root/data" "$validation_root/config" \
        || ! ${pkgs.coreutils}/bin/printf '%s\n' "$fullImport" > "$tmp"; then
        ${pkgs.coreutils}/bin/rm -rf "$validation_root"
        return 1
      fi
      status=0
      XDG_DATA_HOME="$validation_root/data" XDG_CONFIG_HOME="$validation_root/config" \
        ${caddyPackage}/bin/caddy validate --config "$tmp" --adapter caddyfile >/dev/null 2>&1 || status=$?
      ${pkgs.coreutils}/bin/rm -rf "$validation_root"
      return "$status"
    }

    # Load bootstrap before checking unlock state or invoking reconciliation.
    # A failed reload cannot safely leave full routes in memory, so stop Caddy.
    reload_bootstrap

    if [[ -f ${secretRoot}/ready && -f /var/lib/nas-setup/state.json ]]; then
      if ${pkgs.systemd}/bin/systemctl start nas-managed-services-reconcile.service; then
        # Share the editor/compiler authority lock while proving and loading the
        # revision so a concurrent desired-state edit cannot race publication.
        exec 8<"$authorityLockPath"
        ${pkgs.util-linux}/bin/flock -x 8
        # The start is synchronous. Bounded checks tolerate atomic publication
        # becoming visible just after systemd reports the oneshot complete.
        for attempt in 1 2 3; do
          if generated_is_current && managed_is_valid; then
            select_full
            if ${pkgs.systemd}/bin/systemctl is-active --quiet caddy.service \
              && ! reload_caddy; then
              reload_bootstrap
              exit 1
            fi
            exit 0
          fi
          ${pkgs.coreutils}/bin/sleep "$attempt"
        done
      fi
    fi
  '';
in
{
  systemd.services.caddy.serviceConfig.ExecStart = lib.mkForce [
    ""
    "${caddyPackage}/bin/caddy run ${runOptions}"
  ];
  systemd.services.caddy.serviceConfig.ExecReload = lib.mkForce [
    ""
    "${caddyPackage}/bin/caddy reload ${runOptions} --force"
  ];
  systemd.services.caddy.requires = lib.mkIf (
    cfg.networking.firewall.enable
    && cfg.trustedInterfaces != [ ]
    && !cfg.testing.installationReadyFixture
  ) [ "nas-management-network-guard.service" ];
  systemd.services.caddy.after = lib.mkIf (
    cfg.networking.firewall.enable
    && cfg.trustedInterfaces != [ ]
    && !cfg.testing.installationReadyFixture
  ) [ "nas-management-network-guard.service" ];

  systemd.services.nas-caddy-bootstrap = {
    description = "Select the active Caddy configuration (bootstrap vs full)";
    wantedBy = [ "multi-user.target" ];
    before = [ "caddy.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = false;
      ExecStart = renderActive;
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ReadWritePaths = [ "/run/nas-control" ];
      UMask = "0022";
    };
  };

  systemd.paths.nas-caddy-bootstrap = {
    description = "Rebuild the active Caddy config when secret activation changes";
    wantedBy = [ "multi-user.target" ];
    pathConfig = {
      PathChanged = [
        "${secretRoot}/ready"
        "/var/lib/nas-setup/state.json"
        "/run/nas-control/caddy-managed.conf"
      ];
      Unit = "nas-caddy-bootstrap.service";
    };
  };
}
