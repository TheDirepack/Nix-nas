args:
let
  inherit (args)
    authentikPort
    caddyCaExportPath
    cfg
    cockpitPort
    config
    lanHost
    lib
    pkgs
  ;
  sanoidPolicy = {
    autosnap = true;
    autoprune = true;
    frequently = 0;
    hourly = 24;
    daily = 14;
    weekly = 8;
    monthly = 12;
    yearly = 3;
    monitor = true;
    frequently_warn = 0;
    frequently_crit = 0;
    hourly_warn = "90m";
    hourly_crit = "4h";
    daily_warn = "28h";
    daily_crit = "36h";
    weekly_warn = "9d";
    weekly_crit = "12d";
    monthly_warn = "35d";
    monthly_crit = "45d";
    yearly_warn = "400d";
    yearly_crit = "500d";
    capacity_warn = 80;
    capacity_crit = 90;
  };

  sanoidValue = value:
    if lib.isBool value then (if value then "yes" else "no") else toString value;
  sanoidTemplateText = lib.generators.toKeyValue {
    mkKeyValue = key: value: "${key} = ${sanoidValue value}";
  } sanoidPolicy;
  sanoidMonitorConfig = pkgs.writeTextDir "sanoid.conf" ''
    [${cfg.zfsDataset}]
    use_template = production
    recursive = zfs

    [template_production]
    ${sanoidTemplateText}
  '';

  # Keep notification credentials out of process arguments.
  nasAlert = pkgs.writeShellApplication {
    name = "nas-alert";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.curl
    ];
    text = ''
      set -euo pipefail
      title="''${1:-NAS alert on ${config.networking.hostName}}"
      body="''${2:-See journalctl on ${config.networking.hostName}.}"
      if [[ "$title" == *$'\r'* || "$title" == *$'\n'* || ''${#title} -gt 200 ]]; then
        echo "Alert titles must be one line and at most 200 characters." >&2
        exit 2
      fi
      password_file=/run/nas-secrets/observability/ntfy-admin-password
      topic_file=/run/nas-secrets/observability/ntfy-topic

      if [[ ! -r "$password_file" || ! -r "$topic_file" ]]; then
        echo "ntfy runtime credentials are unavailable; alert was not sent." >&2
        exit 0
      fi

      password="$(cat "$password_file")"
      topic="$(cat "$topic_file")"
      [[ -n "$password" && -n "$topic" ]] || {
        echo "ntfy runtime credentials are empty; alert was not sent." >&2
        exit 0
      }

      curl_config="$(mktemp /run/nas-alert-curl.XXXXXX)"
      cleanup() {
        rm -f -- "$curl_config"
        unset password topic
      }
      trap cleanup EXIT HUP INT TERM
      chmod 0600 "$curl_config"
      cat > "$curl_config" <<CURL_CONFIG
url = "http://127.0.0.1:${toString cfg.observability.ntfy.port}/$topic"
user = "admin:$password"
fail
silent
show-error
max-time = 15
CURL_CONFIG
      printf '%s' "$body" | curl --config "$curl_config" \
        --header "Title: $title" \
        --header "Tags: warning" \
        --data-binary @-
    '';
  };

  nasPreflight = pkgs.writeShellApplication {
    name = "nas-preflight";
    excludeShellChecks = [ "SC2015" "SC2016" ];
    runtimeInputs = [
      pkgs.bash
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.gawk
      pkgs.git
      pkgs.gnugrep
      pkgs.gnused
      pkgs.iproute2
      pkgs.jq
      pkgs.nix
      pkgs.nixos-rebuild-ng
      pkgs.python3
      pkgs.skopeo
      pkgs.systemd
      pkgs.util-linux
      pkgs.zfs
    ];
    text = ''
      export NAS_CONFIG_DIR=${lib.escapeShellArg cfg.configurationDir}
      ${builtins.readFile ../../../scripts/preflight.sh}
    '';
  };

  nasUpdate = pkgs.writeShellApplication {
    name = "nas-update";
    excludeShellChecks = [ "SC1007" "SC2086" ];
    runtimeInputs = [
      pkgs.coreutils
      pkgs.curl
      pkgs.findutils
      pkgs.gawk
      pkgs.git
      pkgs.gnugrep
      pkgs.gnused
      pkgs.iproute2
      pkgs.jq
      pkgs.libxml2
      pkgs.nix
      pkgs.nixos-rebuild-ng
      pkgs.nut
      pkgs.skopeo
      pkgs.systemd
      pkgs.zfs
    ];
    text = ''
      export PATH=/run/wrappers/bin:$PATH
      export NAS_CONFIG_DIR=${lib.escapeShellArg cfg.configurationDir}
      export NAS_AUTHENTIK_PORT=${toString authentikPort}
      export NAS_AUTHENTIK_PATH=${lib.escapeShellArg cfg.identity.authentikPath}
      export NAS_CADDY_CA_FILE=${lib.escapeShellArg caddyCaExportPath}
      export NAS_COCKPIT_PORT=${toString cockpitPort}
      export NAS_FIREWALL_ENABLED=${if cfg.networking.enable && cfg.networking.firewall.enable then "1" else "0"}
      export NAS_FIREWALL_ZONE=${lib.escapeShellArg cfg.networking.firewall.zone}
      export NAS_LAN_HOST=${lib.escapeShellArg lanHost}
      export NAS_TRUSTED_INTERFACES=${lib.escapeShellArg (lib.concatStringsSep " " cfg.trustedInterfaces)}
      ${builtins.readFile ../../../scripts/update-nas.sh}
    '';
  };
in
{
  inherit
    sanoidPolicy
    sanoidValue
    sanoidTemplateText
    sanoidMonitorConfig
    nasAlert
    nasPreflight
    nasUpdate
  ;
}
