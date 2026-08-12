args:
let
  inherit (args)
    config
    lib
    pkgs
  ;
  base = import ./base.nix args;
  inherit (base)
    cfg
    identityAdminGroup
    secretRoot
    authentikSecretDir
    authentikEnvironmentFile
    authentikApiTokenFile
    authentikBootstrapTokenFile
    vaultwardenSecretDir
    zfsSecretDir
    aiSecretDir
    observabilitySecretDir
    powerSecretDir
    zfsKeyPath
    caddyCaExportDir
    caddyCaExportPath
    failureAlert
    protectedServiceUnits
  ;
  authentikBootstrapRoot = "${authentikSecretDir}/bootstrap";
  copypartySecretDir = "${secretRoot}/copyparty";
  copypartyAdminPasswordFile = "${copypartySecretDir}/admin-password";
  secretGenerationRoot = "${secretRoot}/generations";
  secretJournal = "${secretRoot}/activation-journal";
  secretLock = "${secretRoot}/activation.lock";
  protectedTarget = "nas-protected-services.target";
  secretPackages = with pkgs; [
    coreutils
    gnugrep
    gnused
    keepassxc
    openssl
    sqlite
    systemd
    util-linux
  ];
  secretPackagePath = lib.makeBinPath secretPackages;
  protectedUnitList = lib.concatStringsSep " " protectedServiceUnits;

  # Shared shell library for staged secret transactions. The active generation is
  # the only subtree exposed through /run/nas-secrets/<service>. Staging happens
  # under generations/<id>, and a single symlink swap publishes the complete set.
  secretTransactionLib = pkgs.writeText "nas-secret-transaction-lib.sh" ''
    set -euo pipefail

    export PATH=${secretPackagePath}:$PATH
    secret_root=${lib.escapeShellArg secretRoot}
    generations_root=${lib.escapeShellArg secretGenerationRoot}
    activation_journal=${lib.escapeShellArg secretJournal}
    activation_lock=${lib.escapeShellArg secretLock}
    protected_target=${lib.escapeShellArg protectedTarget}
    protected_units=${lib.escapeShellArg protectedUnitList}
    admin_group=${lib.escapeShellArg identityAdminGroup}

    sudo_run() {
      if [[ $EUID -eq 0 ]]; then
        "$@"
      else
        sudo "$@"
      fi
    }

    nas_secret_secure_root() {
      sudo_run install -d -m 0750 -o root -g "$admin_group" "$secret_root"
      sudo_run install -d -m 0700 -o root -g root "$generations_root"
      sudo_run touch "$activation_lock"
      sudo_run chown root:root "$activation_lock"
      sudo_run chmod 0600 "$activation_lock"
    }

    nas_secret_current_generation() {
      if sudo_run test -L "$secret_root/current"; then
        sudo_run readlink -f "$secret_root/current"
      fi
    }

    nas_secret_tx_init() {
      local old current_name
      nas_secret_secure_root
      old="$(nas_secret_current_generation || true)"
      current_name="$(date +%s)-$$-$RANDOM"
      NAS_SECRET_STAGE="$generations_root/$current_name"
      NAS_SECRET_OLD="$old"
      sudo_run install -d -m 0700 -o root -g root "$NAS_SECRET_STAGE"
      export NAS_SECRET_STAGE NAS_SECRET_OLD
      nas_secret_write_journal "staging" "$NAS_SECRET_STAGE" "$NAS_SECRET_OLD"
    }

    nas_secret_write_journal() {
      local phase=$1 stage=$2 old=$3 temp
      temp="$(mktemp)"
      printf 'phase=%s\nstage=%s\nold=%s\n' "$phase" "$stage" "$old" > "$temp"
      sudo_run install -m 0600 -o root -g root "$temp" "$activation_journal"
      rm -f -- "$temp"
    }

    nas_secret_read_journal() {
      NAS_SECRET_JOURNAL_PHASE=""
      NAS_SECRET_JOURNAL_STAGE=""
      NAS_SECRET_JOURNAL_OLD=""
      if ! sudo_run test -s "$activation_journal"; then
        export NAS_SECRET_JOURNAL_PHASE NAS_SECRET_JOURNAL_STAGE NAS_SECRET_JOURNAL_OLD
        return 0
      fi
      local line key value
      while IFS= read -r line; do
        key=''${line%%=*}
        value=''${line#*=}
        case "$key" in
          phase) NAS_SECRET_JOURNAL_PHASE=$value ;;
          stage) NAS_SECRET_JOURNAL_STAGE=$value ;;
          old) NAS_SECRET_JOURNAL_OLD=$value ;;
        esac
      done < <(sudo_run cat "$activation_journal")
      export NAS_SECRET_JOURNAL_PHASE NAS_SECRET_JOURNAL_STAGE NAS_SECRET_JOURNAL_OLD
    }

    nas_secret_link_generation() {
      local generation=$1 service
      for service in authentik copyparty vaultwarden zfs ai observability power; do
        if sudo_run test -e "$generation/$service"; then
          sudo_run ln -sfn "current/$service" "$secret_root/$service"
        else
          sudo_run rm -f "$secret_root/$service"
        fi
      done
    }

    nas_secret_swap_current() {
      local generation=$1 parent name temp
      parent="$(dirname "$generation")"
      name="$(basename "$generation")"
      temp="$secret_root/.current.$$"
      sudo_run ln -s "generations/$name" "$temp"
      sudo_run mv -Tf "$temp" "$secret_root/current"
      nas_secret_link_generation "$generation"
    }

    nas_secret_mark_ready() {
      local temp
      temp="$(mktemp)"
      printf 'ready\n' > "$temp"
      sudo_run install -m 0640 -o root -g "$admin_group" "$temp" "$secret_root/ready"
      rm -f -- "$temp"
    }

    nas_secret_clear_ready() {
      sudo_run rm -f "$secret_root/ready"
    }

    nas_secret_stop_protected() {
      sudo_run systemctl stop "$protected_target" 2>/dev/null || true
      local unit
      for unit in $protected_units; do
        sudo_run systemctl stop "$unit" 2>/dev/null || true
      done
    }

    nas_secret_start_protected() {
      sudo_run systemctl start "$protected_target"
    }

    nas_secret_restore_generation() {
      local generation=$1
      if [[ -n $generation ]] && sudo_run test -d "$generation"; then
        nas_secret_swap_current "$generation"
        nas_secret_mark_ready
        nas_secret_start_protected
      else
        sudo_run rm -f "$secret_root/current"
        nas_secret_link_generation /nonexistent
        nas_secret_clear_ready
      fi
    }

    nas_secret_abort_stage() {
      local stage=$1
      if [[ -n $stage ]] && sudo_run test -d "$stage"; then
        sudo_run rm -rf -- "$stage"
      fi
      sudo_run rm -f "$activation_journal"
    }

    nas_secret_prune_generations() {
      local current previous keep path
      current="$(nas_secret_current_generation || true)"
      previous=${1:-}
      keep=" $current $previous "
      while IFS= read -r path; do
        [[ $keep == *" $path "* ]] && continue
        sudo_run rm -rf -- "$path"
      done < <(sudo_run find "$generations_root" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null || true)
    }
  '';

  authentikStage = pkgs.writeShellApplication {
    name = "nas-secret-stage-authentik";
    runtimeInputs = secretPackages;
    text = ''
      source ${secretTransactionLib}
      : "''${NAS_SECRET_STAGE:?NAS_SECRET_STAGE is required}"
      target="$NAS_SECRET_STAGE/authentik"
      install -d -m 0700 "$target" "$target/bootstrap"

      env_file="$target/environment"
      api_file="$target/api-token"
      bootstrap_token="$target/bootstrap-token"
      bootstrap_password="$target/bootstrap/password"
      bootstrap_email="$target/bootstrap/email"

      secret_key="$(openssl rand -base64 60 | tr -d '\n')"
      pg_password="$(openssl rand -base64 36 | tr -d '\n')"
      api_token="$(openssl rand -hex 32)"
      bootstrap_token_value="$(openssl rand -hex 32)"
      bootstrap_password_value="$(openssl rand -base64 36 | tr -d '\n')"

      umask 077
      {
        printf 'AUTHENTIK_SECRET_KEY=%s\n' "$secret_key"
        printf 'AUTHENTIK_POSTGRESQL__PASSWORD=%s\n' "$pg_password"
        printf 'AUTHENTIK_POSTGRESQL__HOST=/run/postgresql\n'
        printf 'AUTHENTIK_POSTGRESQL__NAME=authentik\n'
        printf 'AUTHENTIK_POSTGRESQL__USER=authentik\n'
        printf 'AUTHENTIK_ERROR_REPORTING__ENABLED=false\n'
      } > "$env_file"
      printf '%s\n' "$api_token" > "$api_file"
      printf '%s\n' "$bootstrap_token_value" > "$bootstrap_token"
      printf '%s\n' "$bootstrap_password_value" > "$bootstrap_password"
      printf '%s\n' ${lib.escapeShellArg cfg.identity.authentikBootstrapEmail} > "$bootstrap_email"
      chmod 0600 "$env_file" "$api_file" "$bootstrap_token" "$bootstrap_password" "$bootstrap_email"
    '';
  };

  copypartyStage = pkgs.writeShellApplication {
    name = "nas-secret-stage-copyparty";
    runtimeInputs = secretPackages;
    text = ''
      source ${secretTransactionLib}
      : "''${NAS_SECRET_STAGE:?NAS_SECRET_STAGE is required}"
      target="$NAS_SECRET_STAGE/copyparty"
      install -d -m 0750 "$target"
      password_file="$target/admin-password"
      umask 077
      openssl rand -base64 36 | tr -d '\n' > "$password_file"
      printf '\n' >> "$password_file"
      chmod 0640 "$password_file"
      chown root:${identityAdminGroup} "$password_file"
    '';
  };

  vaultwardenStage = pkgs.writeShellApplication {
    name = "nas-secret-stage-vaultwarden";
    runtimeInputs = secretPackages;
    text = ''
      source ${secretTransactionLib}
      : "''${NAS_SECRET_STAGE:?NAS_SECRET_STAGE is required}"
      target="$NAS_SECRET_STAGE/vaultwarden"
      install -d -m 0750 "$target"
      umask 077
      openssl rand -hex 48 > "$target/admin-token"
      openssl rand -hex 48 > "$target/oidc-client-secret"
      chmod 0640 "$target/admin-token" "$target/oidc-client-secret"
      chown root:${identityAdminGroup} "$target/admin-token" "$target/oidc-client-secret"
    '';
  };

  zfsStage = pkgs.writeShellApplication {
    name = "nas-secret-stage-zfs";
    runtimeInputs = secretPackages;
    text = ''
      source ${secretTransactionLib}
      : "''${NAS_SECRET_STAGE:?NAS_SECRET_STAGE is required}"
      target="$NAS_SECRET_STAGE/zfs"
      install -d -m 0700 "$target"
      if [[ ${if cfg.zfsEncryption.enable then "1" else "0"} == 1 ]]; then
        umask 077
        openssl rand 32 > "$target/dataset-key"
        chmod 0600 "$target/dataset-key"
      fi
    '';
  };

  aiStage = pkgs.writeShellApplication {
    name = "nas-secret-stage-ai";
    runtimeInputs = secretPackages;
    text = ''
      source ${secretTransactionLib}
      : "''${NAS_SECRET_STAGE:?NAS_SECRET_STAGE is required}"
      target="$NAS_SECRET_STAGE/ai"
      install -d -m 0750 "$target"
      umask 077
      touch "$target/llama-swap.env" "$target/open-webui.env" "$target/downloader.env"
      chmod 0640 "$target/llama-swap.env" "$target/open-webui.env" "$target/downloader.env"
      chown root:${identityAdminGroup} "$target/llama-swap.env" "$target/open-webui.env" "$target/downloader.env"
    '';
  };

  observabilityStage = pkgs.writeShellApplication {
    name = "nas-secret-stage-observability";
    runtimeInputs = secretPackages;
    text = ''
      source ${secretTransactionLib}
      : "''${NAS_SECRET_STAGE:?NAS_SECRET_STAGE is required}"
      target="$NAS_SECRET_STAGE/observability"
      install -d -m 0750 "$target"
      umask 077
      touch "$target/grafana.env" "$target/ntfy.env"
      chmod 0640 "$target/grafana.env" "$target/ntfy.env"
      chown root:${identityAdminGroup} "$target/grafana.env" "$target/ntfy.env"
    '';
  };

  powerStage = pkgs.writeShellApplication {
    name = "nas-secret-stage-power";
    runtimeInputs = secretPackages;
    text = ''
      source ${secretTransactionLib}
      : "''${NAS_SECRET_STAGE:?NAS_SECRET_STAGE is required}"
      target="$NAS_SECRET_STAGE/power"
      install -d -m 0750 "$target"
      umask 077
      touch "$target/nut-monitor-password"
      chmod 0640 "$target/nut-monitor-password"
      chown root:${identityAdminGroup} "$target/nut-monitor-password"
    '';
  };

  secretActivation = pkgs.writeShellApplication {
    name = "nas-secrets";
    runtimeInputs = secretPackages ++ [
      authentikStage
      copypartyStage
      vaultwardenStage
      zfsStage
      aiStage
      observabilityStage
      powerStage
    ];
    text = ''
      source ${secretTransactionLib}

      usage() {
        cat <<'USAGE'
Usage: nas-secrets <command>

Commands:
  activate    Stage and atomically activate a new complete secret generation.
  recover     Recover or roll back an interrupted secret activation.
  lock        Stop protected services and hide the active secret generation.
  status      Show active generation and activation state.
USAGE
      }

      require_admin() {
        if [[ $EUID -eq 0 ]]; then
          return 0
        fi
        if ! id -nG | tr ' ' '\n' | grep -Fxq "$admin_group"; then
          echo "This command requires root or membership in $admin_group" >&2
          exit 77
        fi
      }

      check_keepass_source() {
        local db=${lib.escapeShellArg cfg.secrets.keepassDatabase}
        if [[ ! -f $db ]]; then
          echo "KeePass database not found: $db" >&2
          return 1
        fi
        if [[ ! -s $db ]]; then
          echo "KeePass database is empty: $db" >&2
          return 1
        fi
      }

      stage_keepass_export() {
        local export_dir="$NAS_SECRET_STAGE/keepass-export"
        install -d -m 0700 "$export_dir"
        # KeePass remains the durable secret source. Export is intentionally
        # isolated in the staging generation and never published directly.
        check_keepass_source
        install -m 0600 ${lib.escapeShellArg cfg.secrets.keepassDatabase} "$export_dir/database.kdbx"
      }

      stage_generation() {
        nas-secret-stage-authentik
        nas-secret-stage-copyparty
        nas-secret-stage-vaultwarden
        nas-secret-stage-zfs
        nas-secret-stage-ai
        nas-secret-stage-observability
        nas-secret-stage-power
        stage_keepass_export
      }

      validate_stage() {
        local stage=$1
        [[ -s "$stage/authentik/environment" ]]
        [[ -s "$stage/authentik/api-token" ]]
        [[ -s "$stage/authentik/bootstrap-token" ]]
        [[ -s "$stage/authentik/bootstrap/password" ]]
        [[ -s "$stage/authentik/bootstrap/email" ]]
        [[ -s "$stage/copyparty/admin-password" ]]
        if [[ ${if cfg.zfsEncryption.enable then "1" else "0"} == 1 ]]; then
          [[ -s "$stage/zfs/dataset-key" ]]
        fi
        [[ -f "$stage/ai/llama-swap.env" ]]
        [[ -f "$stage/ai/open-webui.env" ]]
        [[ -f "$stage/ai/downloader.env" ]]
        [[ -f "$stage/observability/grafana.env" ]]
        [[ -f "$stage/observability/ntfy.env" ]]
        [[ -f "$stage/power/nut-monitor-password" ]]
      }

      command_activate() {
        require_admin
        exec 9>"$activation_lock"
        flock -x 9
        nas_secret_tx_init
        local stage="$NAS_SECRET_STAGE" old="$NAS_SECRET_OLD"
        trap 'nas_secret_abort_stage "$stage"' ERR INT TERM
        stage_generation
        validate_stage "$stage"
        nas_secret_write_journal "prepared" "$stage" "$old"
        nas_secret_stop_protected
        nas_secret_write_journal "stopped" "$stage" "$old"
        nas_secret_swap_current "$stage"
        nas_secret_mark_ready
        nas_secret_write_journal "swapped" "$stage" "$old"
        if ! nas_secret_start_protected; then
          echo "Protected service startup failed; rolling secrets back" >&2
          nas_secret_stop_protected
          nas_secret_restore_generation "$old"
          nas_secret_abort_stage "$stage"
          trap - ERR INT TERM
          return 1
        fi
        local unit
        for unit in authentik.service authentik-worker.service caddy.service; do
          if ! sudo_run systemctl is-active --quiet "$unit"; then
            echo "Protected service $unit is not active after secret activation" >&2
            nas_secret_stop_protected
            nas_secret_restore_generation "$old"
            nas_secret_abort_stage "$stage"
            trap - ERR INT TERM
            return 1
          fi
        done
        if ! sudo_run test -s ${lib.escapeShellArg authentikApiTokenFile}; then
          echo "Authentik API token was not published after secret activation" >&2
          nas_secret_stop_protected
          nas_secret_restore_generation "$old"
          nas_secret_abort_stage "$stage"
          trap - ERR INT TERM
          return 1
        fi
        if ! sudo_run test -s ${lib.escapeShellArg authentikBootstrapTokenFile}; then
          echo "Authentik bootstrap token was not published after secret activation" >&2
          nas_secret_stop_protected
          nas_secret_restore_generation "$old"
          nas_secret_abort_stage "$stage"
          trap - ERR INT TERM
          return 1
        fi
        nas_secret_write_journal "validated" "$stage" "$old"
        sudo_run rm -f "$activation_journal"
        nas_secret_prune_generations "$old"
        trap - ERR INT TERM
        printf 'Activated secret generation: %s\n' "$stage"
      }

      command_recover() {
        require_admin
        nas_secret_secure_root
        exec 9>"$activation_lock"
        flock -x 9
        nas_secret_read_journal
        local phase="$NAS_SECRET_JOURNAL_PHASE"
        local stage="$NAS_SECRET_JOURNAL_STAGE"
        local old="$NAS_SECRET_JOURNAL_OLD"
        if [[ -z $phase ]]; then
          echo "No interrupted secret transaction is recorded."
          return 0
        fi
        case "$phase" in
          staging|prepared|stopped)
            nas_secret_abort_stage "$stage"
            if [[ -n $old ]] && sudo_run test -d "$old"; then
              nas_secret_restore_generation "$old"
            fi
            ;;
          swapped|validated)
            nas_secret_stop_protected
            if [[ -n $old ]] && sudo_run test -d "$old"; then
              nas_secret_restore_generation "$old"
            else
              nas_secret_clear_ready
            fi
            nas_secret_abort_stage "$stage"
            ;;
          *)
            echo "Unknown secret activation journal phase: $phase" >&2
            return 2
            ;;
        esac
        echo "Recovered interrupted secret activation."
      }

      command_lock() {
        require_admin
        nas_secret_secure_root
        exec 9>"$activation_lock"
        flock -x 9
        nas_secret_stop_protected
        nas_secret_clear_ready
        sudo_run rm -f "$secret_root/current"
        nas_secret_link_generation /nonexistent
        echo "Protected services stopped and active secrets hidden."
      }

      command_status() {
        nas_secret_secure_root
        local current phase
        current="$(nas_secret_current_generation || true)"
        nas_secret_read_journal
        phase="$NAS_SECRET_JOURNAL_PHASE"
        printf 'generation=%s\n' "''${current:-none}"
        printf 'ready=%s\n' "$(sudo_run test -f "$secret_root/ready" && echo yes || echo no)"
        printf 'transaction=%s\n' "''${phase:-none}"
      }

      case "''${1:-}" in
        activate) command_activate ;;
        recover) command_recover ;;
        lock) command_lock ;;
        status) command_status ;;
        -h|--help|help|"") usage ;;
        *)
          usage >&2
          exit 2
          ;;
      esac
    '';
  };

  caddyCaExport = pkgs.writeShellApplication {
    name = "nas-caddy-ca-export";
    runtimeInputs = secretPackages;
    text = ''
      set -euo pipefail
      source ${secretTransactionLib}
      require_file=${lib.escapeShellArg base.caddyInternalCaPath}
      target_dir=${lib.escapeShellArg caddyCaExportDir}
      target=${lib.escapeShellArg caddyCaExportPath}
      sudo_run install -d -m 0750 -o root -g ${identityAdminGroup} "$target_dir"
      sudo_run install -m 0640 -o root -g ${identityAdminGroup} "$require_file" "$target"
    '';
  };

  keepassValidator = pkgs.writeShellApplication {
    name = "nas-keepass-validate";
    runtimeInputs = secretPackages;
    text = ''
      set -euo pipefail
      database=${lib.escapeShellArg cfg.secrets.keepassDatabase}
      [[ -f $database ]] || { echo "KeePass database not found: $database" >&2; exit 1; }
      [[ -s $database ]] || { echo "KeePass database is empty: $database" >&2; exit 1; }
      echo "KeePass source exists and is non-empty."
    '';
  };

  zfsKeyFingerprint = pkgs.writeShellApplication {
    name = "nas-zfs-key-fingerprint";
    runtimeInputs = secretPackages;
    text = ''
      set -euo pipefail
      key=${lib.escapeShellArg zfsKeyPath}
      [[ -s $key ]] || { echo "Missing ZFS key: $key" >&2; exit 1; }
      sha256sum "$key" | awk '{print $1}'
    '';
  };

  secretReadyCheck = pkgs.writeShellApplication {
    name = "nas-secrets-ready";
    runtimeInputs = secretPackages;
    text = ''
      set -euo pipefail
      [[ -f ${lib.escapeShellArg secretRoot}/ready ]]
      current="$(readlink -f ${lib.escapeShellArg secretRoot}/current 2>/dev/null || true)"
      [[ -n $current && -d $current ]]
      [[ -s ${lib.escapeShellArg authentikEnvironmentFile} ]]
      [[ -s ${lib.escapeShellArg authentikApiTokenFile} ]]
      [[ -s ${lib.escapeShellArg copypartyAdminPasswordFile} ]]
      ${lib.optionalString cfg.zfsEncryption.enable ''
      [[ -s ${lib.escapeShellArg zfsKeyPath} ]]
      ''}
    '';
  };

  secretFaultTest = pkgs.writeShellApplication {
    name = "nas-secret-fault-test";
    runtimeInputs = secretPackages;
    text = ''
      set -euo pipefail
      work="$(mktemp -d)"
      trap 'rm -rf "$work"' EXIT
      mkdir -p "$work/root/generations/old" "$work/root/generations/new"
      ln -s generations/old "$work/root/current"
      printf old > "$work/root/generations/old/marker"
      printf new > "$work/root/generations/new/marker"
      ln -s generations/new "$work/root/.current.test"
      mv -Tf "$work/root/.current.test" "$work/root/current"
      [[ $(cat "$work/root/current/marker") == new ]]
      ln -s generations/old "$work/root/.current.rollback"
      mv -Tf "$work/root/.current.rollback" "$work/root/current"
      [[ $(cat "$work/root/current/marker") == old ]]
      echo "secret generation swap rollback test passed"
    '';
  };

in
{
  inherit
    authentikBootstrapRoot
    copypartySecretDir
    copypartyAdminPasswordFile
    secretGenerationRoot
    secretJournal
    secretLock
    protectedTarget
    secretTransactionLib
    secretActivation
    caddyCaExport
    keepassValidator
    zfsKeyFingerprint
    secretReadyCheck
    secretFaultTest
    authentikStage
    copypartyStage
    vaultwardenStage
    zfsStage
    aiStage
    observabilityStage
    powerStage
  ;
}
