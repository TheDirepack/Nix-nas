args:
let
  inherit (args)
    authentikPort
    bootstrapPassword
    cfg
    lib
    pkgs
    secretRoot
  ;
  pythonYaml = pkgs.python3.withPackages (pythonPackages: [ pythonPackages.pyyaml ]);
  nasSecrets = pkgs.writeShellApplication {
    name = "nas-secrets";
    excludeShellChecks = [ "SC2329" ];
    runtimeInputs = [
      pkgs.apacheHttpd
      pkgs.libargon2
      pkgs.coreutils
      pkgs.curl
      pkgs.findutils
      pkgs.gnugrep
      pkgs.gnused
      pkgs.keepassxc
      pkgs.openssl
      pythonYaml
      pkgs.systemd
      pkgs.util-linux
    ];
    text = ''
      export PATH=/run/wrappers/bin:$PATH
      set -euo pipefail
      umask 0077

      database=${lib.escapeShellArg cfg.secrets.keepassDatabase}
      key_file=${lib.escapeShellArg (if cfg.secrets.keepassKeyFile == null then "" else cfg.secrets.keepassKeyFile)}
      secret_group=${lib.escapeShellArg cfg.secrets.keepassGroup}
      secret_root=${lib.escapeShellArg secretRoot}
      keepass_password=""
      password_from_stdin=false

      cleanup_password() {
        unset keepass_password
      }
      trap cleanup_password EXIT HUP INT TERM

      acquire_lock() {
        exec 8>/run/lock/nas-secrets.lock
        flock --nonblock 8 || {
          echo "Another NAS secret operation is already running." >&2
          exit 1
        }
      }

      require_database() {
        [[ -f "$database" ]] || {
          echo "KeePassXC database not found: $database" >&2
          echo "Create or restore the KDBX database, then configure nas.secrets.keepassDatabase." >&2
          exit 1
        }
        if [[ -n "$key_file" && ! -f "$key_file" ]]; then
          echo "KeePassXC key file not found: $key_file" >&2
          exit 1
        fi
      }

      prompt_unlock() {
        require_database
        if $password_from_stdin; then
          IFS= read -r keepass_password || {
            echo "Unable to read the KeePass database password from standard input." >&2
            exit 1
          }
        else
          read -r -s -p "KeePass database password: " keepass_password
          echo
        fi
        [[ -n "$keepass_password" ]] || {
          echo "The KeePass database password cannot be empty." >&2
          exit 1
        }
        # keepassxc >= 2.7 reads a piped database password from stdin without an explicit flag.
        local args=(db-info --quiet)
        [[ -n "$key_file" ]] && args+=(--key-file "$key_file")
        args+=("$database")
        if ! printf '%s\n' "$keepass_password" | keepassxc-cli "''${args[@]}" >/dev/null 2>&1; then
          echo "Unable to unlock the KeePassXC database." >&2
          exit 1
        fi
      }

      kp_args() {
        KP_ARGS=(--quiet)
        if [[ -n "$key_file" ]]; then
          KP_ARGS+=(--key-file "$key_file")
        fi
      }

      entry_path() {
        printf '%s/%s' "$secret_group" "$1"
      }

      ensure_group() {
        kp_args
        if printf '%s\n' "$keepass_password" | keepassxc-cli ls "''${KP_ARGS[@]}" "$database" "$secret_group" >/dev/null 2>&1; then
          return 0
        fi
        if ! printf '%s\n' "$keepass_password" | keepassxc-cli mkdir "''${KP_ARGS[@]}" "$database" "$secret_group" >/dev/null 2>&1; then
          echo "Unable to ensure KeePassXC group: $secret_group" >&2
          exit 1
        fi
      }

      has_secret() {
        local key="$1" listing
        kp_args
        if ! listing="$(printf '%s\n' "$keepass_password" | keepassxc-cli ls "''${KP_ARGS[@]}" --flatten "$database" "$secret_group" 2>/dev/null)"; then
          echo "Unable to inspect the KeePassXC secret group." >&2
          exit 1
        fi
        grep -Fxq -- "$key" <<<"$listing"
      }

      store_value() {
        local key="$1" value="$2" path
        path="$(entry_path "$key")"
        kp_args
        if has_secret "$key"; then
          printf '%s\n%s\n' "$keepass_password" "$value" | keepassxc-cli edit "''${KP_ARGS[@]}" -p "$database" "$path" >/dev/null
        else
          printf '%s\n%s\n' "$keepass_password" "$value" | keepassxc-cli add "''${KP_ARGS[@]}" -p "$database" "$path" >/dev/null
        fi
      }

      remove_value() {
        local key="$1" path
        if ! has_secret "$key"; then
          return 0
        fi
        path="$(entry_path "$key")"
        kp_args
        if ! printf '%s\n' "$keepass_password" | keepassxc-cli rm "''${KP_ARGS[@]}" "$database" "$path" >/dev/null 2>&1; then
          echo "Unable to remove KeePassXC entry: $path" >&2
          return 1
        fi
      }

      get_secret() {
        local key="$1" path value
        path="$(entry_path "$key")"
        kp_args
        value="$(printf '%s\n' "$keepass_password" | keepassxc-cli show "''${KP_ARGS[@]}" --show-protected -a Password "$database" "$path")" || {
          echo "Unable to retrieve KeePassXC entry: $path" >&2
          exit 1
        }
        [[ -n "$value" ]] || {
          echo "KeePassXC returned an empty password for: $path" >&2
          exit 1
        }
        printf '%s' "$value"
      }

      get_secret_optional() {
        has_secret "$1" || return 0
        get_secret "$1"
      }

      require_secret_atom() {
        local value="$1" label="$2" minimum="''${3:-8}" maximum="''${4:-4096}"
        if (( ''${#value} < minimum || ''${#value} > maximum )) || [[ ! "$value" =~ ^[A-Za-z0-9._~+/=:@-]+$ ]]; then
          echo "$label has an unsafe or unexpected format in KeePassXC." >&2
          return 1
        fi
      }

      require_secret_hex() {
        local value="$1" expected="$2" label="$3"
        if (( ''${#value} != expected )) || [[ ! "$value" =~ ^[0-9A-Fa-f]+$ ]]; then
          echo "$label has an unsafe or unexpected format in KeePassXC." >&2
          return 1
        fi
      }

      require_ntfy_topic() {
        local value="$1"
        if (( ''${#value} < 8 || ''${#value} > 128 )) || [[ ! "$value" =~ ^[A-Za-z0-9_-]+$ ]]; then
          echo "ntfy alert topic has an unsafe or unexpected format in KeePassXC." >&2
          return 1
        fi
      }

      require_huggingface_token() {
        local value="$1"
        [[ -z "$value" || "$value" =~ ^hf_[A-Za-z0-9]{20,}$ ]] || {
          echo "Hugging Face token has an unsafe or unexpected format in KeePassXC." >&2
          return 1
        }
      }

      validate_ai_provider_id() {
        [[ "''${1:-}" =~ ^[a-z][a-z0-9-]{0,47}$ ]] || {
          echo "AI provider ID must use lowercase letters, digits, and hyphens." >&2
          exit 2
        }
      }

      ai_provider_env_name() {
        validate_ai_provider_id "$1"
        local value
        value="''${1^^}"
        value="''${value//-/_}"
        printf 'LLAMA_SWAP_PEER_%s_API_KEY' "$value"
      }

      ai_provider_pairs() {
        local config=/var/lib/nas-llama-swap/config.yaml
        [[ -f "$config" ]] || return 0
        python3 - "$config" <<'PY_AI_PROVIDERS'
import re
import sys
import yaml

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    config = yaml.safe_load(handle) or {}
peers = config.get("peers") or {}
if not isinstance(peers, dict):
    raise SystemExit("llama-swap peers configuration is not an object")
provider_re = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
env_re = re.compile(r"^\$\{env\.([A-Z][A-Z0-9_]*)\}$")
for provider, peer in sorted(peers.items()):
    if not isinstance(provider, str) or not provider_re.fullmatch(provider) or not isinstance(peer, dict):
        continue
    value = peer.get("apiKey")
    if not isinstance(value, str):
        continue
    match = env_re.fullmatch(value)
    if match:
        expected = "LLAMA_SWAP_PEER_" + provider.upper().replace("-", "_") + "_API_KEY"
        if match.group(1) != expected:
            raise SystemExit(f"peer {provider} references an unexpected API-key environment variable")
        print(provider + "\t" + match.group(1))
PY_AI_PROVIDERS
      }

      stage_ai_provider_runtime_key() {
        local provider="$1" value="$2" env_name existing temp
        env_name="$(ai_provider_env_name "$provider")"
        require_secret_atom "$value" "AI provider API key" 8 4096
        [[ -f "$secret_root/ready" ]] || return 0
        existing="$secret_root/ai/llama-swap.env"
        [[ -f "$existing" ]] || return 0
        temp="$(mktemp "$secret_root/.llama-swap.env.XXXXXX")"
        trap 'rm -f "$temp"' RETURN
        grep -v -E "^''${env_name}=" "$existing" > "$temp" || true
        printf '%s=%s\n' "$env_name" "$value" >> "$temp"
        sudo install -m 0400 -o nas-ai -g nas-ai "$temp" "$existing"
        rm -f "$temp"
        trap - RETURN
        if [[ -z "''${NAS_SKIP_LLAMA_SWAP_RESTART:-}" ]] && systemctl is-active --quiet nas-llama-swap.service; then
          sudo systemctl restart nas-llama-swap.service
        fi
      }

      remove_ai_provider_runtime_key() {
        local provider="$1" env_name existing temp
        env_name="$(ai_provider_env_name "$provider")"
        [[ -f "$secret_root/ready" ]] || return 0
        existing="$secret_root/ai/llama-swap.env"
        [[ -f "$existing" ]] || return 0
        temp="$(mktemp "$secret_root/.llama-swap.env.XXXXXX")"
        trap 'rm -f "$temp"' RETURN
        grep -v -E "^''${env_name}=" "$existing" > "$temp" || true
        sudo install -m 0400 -o nas-ai -g nas-ai "$temp" "$existing"
        rm -f "$temp"
        trap - RETURN
        if [[ -z "''${NAS_SKIP_LLAMA_SWAP_RESTART:-}" ]] && systemctl is-active --quiet nas-llama-swap.service; then
          sudo systemctl restart nas-llama-swap.service
        fi
      }

      store_random_if_missing() {
        local key="$1" label="$2" bytes="$3" value
        if has_secret "$key"; then
          printf 'KeePassXC item already exists: %s\n' "$label"
          return
        fi
        value="$(openssl rand -hex "$bytes")"
        store_value "$key" "$value"
        unset value
        printf 'Created KeePassXC item: %s\n' "$label"
      }

      hash_password() {
        local password="$1" salt digest
        salt="$(openssl rand -hex 16)"
        digest="$(printf '%s' "$password" | argon2 "$salt" -id -e -t 3 -m 16 -p 4)"
        [[ "$digest" == \$argon2id\$* ]] || {
          echo "Argon2 did not return an encoded Argon2id digest." >&2
          exit 1
        }
        printf '%s' "$digest"
      }

      bcrypt_password() {
        local username="$1" password="$2" line
        # htpasswd -i reads the password from stdin; never expose secrets in argv.
        line="$(printf '%s\n' "$password" | htpasswd -nBiC 12 "$username")"
        printf '%s' "''${line#*:}"
      }

      command_init() {
        acquire_lock
        prompt_unlock
        ensure_group
        store_random_if_missing authentik-secret-key "Authentik secret key" 64
        store_random_if_missing authentik-bootstrap-token "Authentik bootstrap token" 32
        if ! has_secret authentik-api-token; then
          store_value authentik-api-token "$(get_secret authentik-bootstrap-token)"
          echo "Created KeePassXC item: Authentik NAS API token (initially the bootstrap token)"
        fi
        if ! has_secret authentik-bootstrap-password; then
          store_value authentik-bootstrap-password ${lib.escapeShellArg bootstrapPassword}
          echo "Created KeePassXC item: Authentik bootstrap administrator password"
        fi
        store_random_if_missing state-bundle-signing-key "NAS state bundle HMAC signing key" 32
        ${lib.optionalString (cfg.observability.enable && cfg.observability.grafana.enable) ''
        store_random_if_missing grafana-secret-key "Grafana signing and data-source secret key" 32
        ''}
        ${lib.optionalString cfg.observability.ntfy.enable ''
        store_random_if_missing ntfy-admin-password "ntfy administrator password" 24
        store_random_if_missing ntfy-alert-topic "ntfy private alert topic" 16
        ''}
        ${lib.optionalString (cfg.power.ups.enable && cfg.power.ups.web.enable) ''
        store_random_if_missing nut-webgui-server-key "NUT Web GUI session signing key" 32
        ''}
        ${lib.optionalString cfg.zfsEncryption.enable ''
        store_random_if_missing zfs-dataset-key "ZFS native encryption key" 32
        ''}
        ${lib.optionalString cfg.ai.enable ''
        store_random_if_missing llama-swap-api-key "llama-swap API key" 32
        ${lib.optionalString cfg.ai.codingAgent.enable ''store_random_if_missing coding-agent-api-key "Pi coding-agent llama-swap client key" 32''}
        store_random_if_missing open-webui-secret "Open WebUI signing secret" 32
        store_random_if_missing open-webui-admin-password "Open WebUI bootstrap administrator password" 24
        ''}
        ${lib.optionalString cfg.vaultwarden.enable ''
        store_random_if_missing vaultwarden-oidc-client-secret "Vaultwarden Authentik OIDC client secret" 32
        store_random_if_missing vaultwarden-admin "Vaultwarden admin token" 32
        ''}
        echo
        echo "Secret initialization complete. Human identity and access policy remain in Authentik."
        echo "Run: nas-secrets activate"
      }

      command_adopt_authentik_bootstrap_stdin() {
        acquire_lock
        password_from_stdin=true
        prompt_unlock
        ensure_group
        local secret_key token
        IFS= read -r secret_key || { echo "Unable to read the Authentik bootstrap secret key." >&2; exit 1; }
        IFS= read -r token || { echo "Unable to read the Authentik bootstrap token." >&2; exit 1; }
        if IFS= read -r _; then
          echo "Unexpected extra input while adopting Authentik bootstrap authority." >&2
          exit 1
        fi
        require_secret_hex "$secret_key" 128 "Authentik bootstrap secret key"
        require_secret_hex "$token" 64 "Authentik bootstrap token"
        store_value authentik-secret-key "$secret_key"
        store_value authentik-bootstrap-token "$token"
        store_value authentik-api-token "$token"
        if ! has_secret authentik-bootstrap-password; then
          store_value authentik-bootstrap-password ${lib.escapeShellArg bootstrapPassword}
        fi
        unset secret_key token
        echo "Adopted the running first-boot Authentik authority."
      }

      install_secret() {
        local source="$1" target="$2" owner="$3" group="$4"
        sudo install -m 0400 -o "$owner" -g "$group" "$source" "$target"
      }

      # Limit transient secret variables to the activation scope.
      command_activate() (
        set -Eeuo pipefail
        local setup_activation="''${1:-false}"
        acquire_lock
        prompt_unlock

        local local_stage root_stage previous transaction_dir runtime_base
        local bootstrap_token_reused=false
        local authentik_secret authentik_bootstrap_token authentik_bootstrap_password
        ${lib.optionalString cfg.vaultwarden.enable ''local vaultwarden_client_secret vaultwarden_admin_token vaultwarden_admin_hash''}
        ${lib.optionalString cfg.ai.enable ''local llama_swap_api_key open_webui_secret open_webui_admin_password huggingface_token''}
        ${lib.optionalString (cfg.ai.enable && cfg.ai.codingAgent.enable) ''local coding_agent_api_key''}
        ${lib.optionalString cfg.ai.enable ''local provider_id provider_env provider_key''}
        ${lib.optionalString cfg.observability.ntfy.enable ''local ntfy_password ntfy_hash ntfy_topic''}
        local state_bundle_signing_key
        sudo install -d -m 0711 -o root -g root /run/nas-secret-runtime/staging
        runtime_base="/run/nas-secret-runtime/staging/$(id -u)"
        sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" "$runtime_base"
        if [[ ! -d "$runtime_base" || -L "$runtime_base" || "$(stat -c '%u' "$runtime_base")" != "$(id -u)" || "$((8#$(stat -c '%a' "$runtime_base") & 8#077))" -ne 0 ]]; then
          echo "Refusing to stage secrets: a private user runtime directory is unavailable." >&2
          exit 70
        fi
        local_stage="$(mktemp -d "$runtime_base/nas-secrets.XXXXXX")"
        if [[ "$(stat -c '%a' "$local_stage")" != "700" ]]; then
          echo "Refusing to stage secrets: temporary directory is not mode 0700." >&2
          exit 70
        fi
        sudo install -d -m 0700 -o root -g root /run/nas-secret-runtime/transactions
        transaction_dir="$(sudo mktemp -d /run/nas-secret-runtime/transactions/transaction.XXXXXX)"
        root_stage="$transaction_dir/new"
        previous="$transaction_dir/previous"

        # Nix substitutes the immutable library store path.
        # shellcheck disable=SC1091
        source ${../../../scripts/lib/nas-secret-transaction.sh}
        nas_secret_tx_init "$secret_root" "$root_stage" "$previous" nas-protected-services.target "$transaction_dir"

        cleanup() {
          local rc=$?
          trap - EXIT HUP INT TERM
          local transaction_cleanup_rc
          rm -rf "$local_stage"
          set +e
          nas_secret_tx_cleanup "$rc"
          transaction_cleanup_rc=$?
          set -e
          cleanup_password
          if [[ "$transaction_cleanup_rc" -eq 125 ]]; then
            echo "Secret activation failed and rollback was incomplete." >&2
            exit 125
          fi
          exit "$rc"
        }
        trap cleanup EXIT
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM

        install -d -m 0700 "$local_stage"/{authentik,vaultwarden,zfs,ai,observability,power,state}

        authentik_secret="$(get_secret authentik-secret-key)"
        authentik_bootstrap_token="$(get_secret_optional authentik-bootstrap-token)"
        authentik_bootstrap_password="$(get_secret_optional authentik-bootstrap-password)"
        local authentik_api_token
        authentik_api_token="$(get_secret authentik-api-token)"
        require_secret_hex "$authentik_secret" 128 "Authentik secret key"
        require_secret_atom "$authentik_api_token" "Authentik API token" 20 4096
        if [[ -n "$authentik_bootstrap_token" || -n "$authentik_bootstrap_password" ]]; then
          require_secret_hex "$authentik_bootstrap_token" 64 "Authentik bootstrap token"
          require_secret_atom "$authentik_bootstrap_password" "Authentik bootstrap password" 20 4096
        fi
        cat > "$local_stage/authentik/environment" <<AUTHENTIK_ENV
AUTHENTIK_SECRET_KEY=$authentik_secret
AUTHENTIK_ENV
        if [[ -n "$authentik_bootstrap_token" ]]; then
          cat >> "$local_stage/authentik/environment" <<AUTHENTIK_BOOTSTRAP_ENV
AUTHENTIK_BOOTSTRAP_TOKEN=$authentik_bootstrap_token
AUTHENTIK_BOOTSTRAP_PASSWORD=$authentik_bootstrap_password
AUTHENTIK_BOOTSTRAP_EMAIL=${lib.escapeShellArg cfg.identity.bootstrapEmail}
AUTHENTIK_BOOTSTRAP_ENV
        fi
        printf '%s' "$authentik_api_token" > "$local_stage/authentik/api-token"
        if [[ -n "$authentik_bootstrap_token" ]]; then
          printf '%s' "$authentik_bootstrap_token" > "$local_stage/authentik/bootstrap-token"
        fi
        state_bundle_signing_key="$(get_secret state-bundle-signing-key)"
        require_secret_hex "$state_bundle_signing_key" 64 "State bundle signing key"
        printf '%s' "$state_bundle_signing_key" > "$local_stage/state/bundle-signing-key"
        if [[ -n "$authentik_bootstrap_token" && "$authentik_api_token" == "$authentik_bootstrap_token" ]]; then
          bootstrap_token_reused=true
          cat > "$local_stage/authentik-token-warning" <<'TOKEN_WARNING'
The Authentik runtime API token is still the bootstrap token. Create a scoped service-account token, store it with `nas-secrets set-authentik-token`, and activate secrets again.
TOKEN_WARNING
          echo "WARNING: Authentik runtime API token is still the bootstrap token." >&2
        fi

        ${lib.optionalString (cfg.observability.enable && cfg.observability.grafana.enable) ''
        printf '%s' "$(get_secret grafana-secret-key)" > "$local_stage/observability/grafana-secret-key"
        ''}
        ${lib.optionalString cfg.observability.ntfy.enable ''
        ntfy_password="$(get_secret ntfy-admin-password)"
        ntfy_topic="$(get_secret ntfy-alert-topic)"
        require_secret_atom "$ntfy_password" "ntfy administrator password" 20 4096
        require_ntfy_topic "$ntfy_topic"
        ntfy_hash="$(bcrypt_password admin "$ntfy_password")"
        cat > "$local_stage/observability/ntfy-environment" <<NTFY_ENV
NTFY_AUTH_USERS=admin:$ntfy_hash:admin
NTFY_AUTH_DEFAULT_ACCESS=deny-all
NTFY_ENABLE_LOGIN=true
NTFY_ENV
        printf '%s' "$ntfy_topic" > "$local_stage/observability/ntfy-topic"
        printf '%s' "$ntfy_password" > "$local_stage/observability/ntfy-admin-password"
        ''}
        ${lib.optionalString (cfg.power.ups.enable && cfg.power.ups.web.enable) ''
        printf '%s' "$(get_secret nut-webgui-server-key)" > "$local_stage/power/nut-webgui-server-key"
        ''}
        ${lib.optionalString cfg.zfsEncryption.enable ''
        printf '%s' "$(get_secret zfs-dataset-key)" > "$local_stage/zfs/dataset-key"
        ''}
        ${lib.optionalString cfg.ai.enable ''
        llama_swap_api_key="$(get_secret llama-swap-api-key)"
        ${lib.optionalString cfg.ai.codingAgent.enable ''coding_agent_api_key="$(get_secret coding-agent-api-key)"''}
        open_webui_secret="$(get_secret open-webui-secret)"
        open_webui_admin_password="$(get_secret open-webui-admin-password)"
        huggingface_token="$(get_secret_optional huggingface-token)"
        require_secret_atom "$llama_swap_api_key" "llama-swap API key" 8 4096
        ${lib.optionalString cfg.ai.codingAgent.enable ''require_secret_atom "$coding_agent_api_key" "Pi coding-agent API key" 8 4096''}
        require_secret_atom "$open_webui_secret" "Open WebUI signing secret" 8 4096
        require_secret_atom "$open_webui_admin_password" "Open WebUI bootstrap password" 8 4096
        require_huggingface_token "$huggingface_token"
        printf 'LLAMA_SWAP_API_KEY=%s\n' "$llama_swap_api_key" > "$local_stage/ai/llama-swap.env"
        ${lib.optionalString cfg.ai.codingAgent.enable ''
        printf 'LLAMA_SWAP_CODING_API_KEY=%s\n' "$coding_agent_api_key" >> "$local_stage/ai/llama-swap.env"
        printf '%s' "$coding_agent_api_key" > "$local_stage/ai/coding-agent-api-key"
        ''}
        while IFS=$'\t' read -r provider_id provider_env; do
          [[ -n "$provider_id" && -n "$provider_env" ]] || continue
          provider_key="$(get_secret_optional "ai-provider-$provider_id")"
          [[ -n "$provider_key" ]] || {
            echo "llama-swap provider $provider_id requires a KeePass API key that is not configured." >&2
            exit 1
          }
          require_secret_atom "$provider_key" "llama-swap provider $provider_id API key" 8 4096
          printf '%s=%s\n' "$provider_env" "$provider_key" >> "$local_stage/ai/llama-swap.env"
        done < <(ai_provider_pairs)
        printf 'WEBUI_SECRET_KEY=%s\nWEBUI_ADMIN_PASSWORD=%s\n' "$open_webui_secret" "$open_webui_admin_password" > "$local_stage/ai/open-webui.env"
        printf 'HF_TOKEN=%s\n' "$huggingface_token" > "$local_stage/ai/hfdownloader.env"
        ''}
        ${lib.optionalString cfg.vaultwarden.enable ''
        vaultwarden_client_secret="$(get_secret vaultwarden-oidc-client-secret)"
        vaultwarden_admin_token="$(get_secret vaultwarden-admin)"
        require_secret_atom "$vaultwarden_client_secret" "Vaultwarden OIDC client secret" 8 4096
        require_secret_atom "$vaultwarden_admin_token" "Vaultwarden administrator token" 8 4096
        vaultwarden_admin_hash="$(hash_password "$vaultwarden_admin_token")"
        printf "ADMIN_TOKEN='%s'\nSSO_CLIENT_SECRET='%s'\n" "$vaultwarden_admin_hash" "$vaultwarden_client_secret" > "$local_stage/vaultwarden/environment"
        ''}

        find "$local_stage" -type f -exec chmod 0600 {} +
        sudo -v
        sudo install -d -m 0711 -o root -g root "$root_stage"
        sudo install -d -m 0750 -o root -g authentik "$root_stage/authentik"
        sudo install -d -m 0700 -o root -g root "$root_stage/state"
        ${lib.optionalString cfg.vaultwarden.enable ''sudo install -d -m 0700 -o root -g root "$root_stage/vaultwarden"''}
        ${lib.optionalString cfg.zfsEncryption.enable ''sudo install -d -m 0700 -o root -g root "$root_stage/zfs"''}
        ${lib.optionalString cfg.ai.enable ''sudo install -d -m 0711 -o root -g root "$root_stage/ai"''}
        ${lib.optionalString (cfg.observability.enable || cfg.observability.ntfy.enable) ''sudo install -d -m 0750 -o root -g nas-observability "$root_stage/observability"''}
        ${lib.optionalString (cfg.power.ups.enable && cfg.power.ups.web.enable) ''sudo install -d -m 0700 -o root -g root "$root_stage/power"''}

        install_secret "$local_stage/authentik/environment" "$root_stage/authentik/environment" authentik authentik
        install_secret "$local_stage/authentik/api-token" "$root_stage/authentik/api-token" root root
        if [[ -n "$authentik_bootstrap_token" ]]; then
          install_secret "$local_stage/authentik/bootstrap-token" "$root_stage/authentik/bootstrap-token" root root
        fi
        install_secret "$local_stage/state/bundle-signing-key" "$root_stage/state/bundle-signing-key" root root
        if $bootstrap_token_reused; then
          install_secret "$local_stage/authentik-token-warning" "$root_stage/authentik-token-warning" root root
        fi
        ${lib.optionalString cfg.vaultwarden.enable ''install_secret "$local_stage/vaultwarden/environment" "$root_stage/vaultwarden/environment" root root''}
        ${lib.optionalString cfg.zfsEncryption.enable ''install_secret "$local_stage/zfs/dataset-key" "$root_stage/zfs/dataset-key" root root''}
        ${lib.optionalString cfg.ai.enable ''
        install_secret "$local_stage/ai/llama-swap.env" "$root_stage/ai/llama-swap.env" nas-ai nas-ai
        ${lib.optionalString cfg.ai.codingAgent.enable ''install_secret "$local_stage/ai/coding-agent-api-key" "$root_stage/ai/coding-agent-api-key" nas-code-agent nas-code-agent''}
        install_secret "$local_stage/ai/open-webui.env" "$root_stage/ai/open-webui.env" root root
        install_secret "$local_stage/ai/hfdownloader.env" "$root_stage/ai/hfdownloader.env" hfdownloader hfdownloader
        ''}
        ${lib.optionalString (cfg.observability.enable && cfg.observability.grafana.enable) ''install_secret "$local_stage/observability/grafana-secret-key" "$root_stage/observability/grafana-secret-key" grafana grafana''}
        ${lib.optionalString cfg.observability.ntfy.enable ''
        install_secret "$local_stage/observability/ntfy-environment" "$root_stage/observability/ntfy-environment" root root
        install_secret "$local_stage/observability/ntfy-topic" "$root_stage/observability/ntfy-topic" nas-observability nas-observability
        install_secret "$local_stage/observability/ntfy-admin-password" "$root_stage/observability/ntfy-admin-password" nas-observability nas-observability
        ''}
        ${lib.optionalString (cfg.power.ups.enable && cfg.power.ups.web.enable) ''install_secret "$local_stage/power/nut-webgui-server-key" "$root_stage/power/nut-webgui-server-key" root root''}
        sudo install -m 0400 -o root -g root /dev/null "$root_stage/ready"

        nas_secret_tx_swap

        sudo systemctl reset-failed \
          postgresql.service postgresql-setup.service \
          authentik-migrate.service authentik-worker.service authentik.service caddy.service
        if [[ "$setup_activation" == true ]]; then
          if ! sudo systemctl start postgresql.service \
            || ! sudo systemctl start authentik-migrate.service \
            || ! sudo systemctl start --job-mode=ignore-dependencies authentik.service \
            || ! sudo systemctl start --job-mode=ignore-dependencies authentik-worker.service \
            || ! sudo systemctl start --job-mode=ignore-dependencies caddy.service; then
            echo "Setup identity services failed to start; inspect systemctl --failed." >&2
            exit 71
          fi
        elif ! sudo systemctl start nas-protected-services.target; then
          echo "Protected service target failed to start; inspect systemctl --failed." >&2
          exit 71
        fi

        for unit in authentik.service authentik-worker.service caddy.service; do
          if sudo systemctl is-failed --quiet "$unit"; then
            echo "Protected service entered the failed state: $unit" >&2
            exit 72
          fi
        done

        if timeout 90s curl --fail --silent --show-error \
          --connect-timeout 1 --max-time 2 \
          --retry 90 --retry-delay 1 --retry-connrefused --retry-all-errors \
          http://127.0.0.1:${toString authentikPort}${cfg.identity.authentikPath}-/health/ready/ >/dev/null; then
          :
        else
          readiness_status=$?
          if sudo systemctl is-failed --quiet authentik.service; then
            echo "Authentik failed while waiting for API readiness." >&2
            exit 72
          fi
          if [[ "$readiness_status" -eq 124 ]]; then
            echo "Authentik remained active but did not become API-ready within 90 seconds." >&2
          else
            echo "Authentik readiness probe failed with curl/timeout status $readiness_status." >&2
          fi
          exit 73
        fi

        for unit in authentik.service authentik-worker.service caddy.service; do
          if ! sudo systemctl is-active --quiet "$unit"; then
            echo "Protected service is not active after readiness validation: $unit" >&2
            exit 74
          fi
        done

        nas_secret_tx_commit
        echo "Runtime service secrets activated. Authentik remains the identity source of truth."
      )

      command_status() {
        [[ -f "$secret_root/ready" ]] && echo "Runtime secrets: active" || echo "Runtime secrets: inactive"
        [[ -f "$database" ]] && echo "KeePassXC database: configured" || echo "KeePassXC database: missing"
        systemctl is-active authentik.service 2>/dev/null || true
        systemctl is-active nas-v2-timer-identity-sync-0.timer 2>/dev/null || true
        if [[ -f "$secret_root/authentik-token-warning" ]]; then
          echo "Authentik API token: WARNING — bootstrap token still in use"
        else
          echo "Authentik API token: scoped-token warning not present"
        fi
      }

      command_stop() {
        acquire_lock
        sudo systemctl stop nas-protected-services.target
        sudo rm -rf "$secret_root"
        echo "Protected services stopped and runtime secrets removed. KeePassXC was not modified."
      }

      command_check_authentik_token() {
        acquire_lock
        prompt_unlock
        local bootstrap api
        bootstrap="$(get_secret authentik-bootstrap-token)"
        api="$(get_secret authentik-api-token)"
        if [[ "$bootstrap" == "$api" ]]; then
          echo "WARNING: Authentik runtime API token is still the bootstrap token." >&2
          return 1
        fi
        echo "Authentik runtime API token differs from the bootstrap token."
      }

      command_set_authentik_token() {
        acquire_lock
        prompt_unlock
        ensure_group
        local token
        read -r -s -p "Authentik API token: " token
        echo
        [[ "$token" =~ ^[A-Za-z0-9._~-]{20,}$ ]] || {
          echo "Authentik API token format is invalid." >&2
          exit 1
        }
        store_value authentik-api-token "$token"
        unset token
        echo "Authentik API token stored. Run nas-secrets activate to stage it."
      }

      command_set_authentik_token_stdin() {
        acquire_lock
        password_from_stdin=true
        prompt_unlock
        ensure_group
        local token
        IFS= read -r token || { echo "Unable to read the Authentik API token from standard input." >&2; exit 1; }
        if IFS= read -r _; then
          echo "Unexpected extra input while setting the Authentik API token." >&2
          exit 1
        fi
        [[ "$token" =~ ^[A-Za-z0-9._~-]{20,}$ ]] || {
          echo "Authentik API token format is invalid." >&2
          exit 1
        }
        store_value authentik-api-token "$token"
        unset token
        echo "Authentik API token stored."
      }

      command_retire_authentik_bootstrap_stdin() {
        acquire_lock
        password_from_stdin=true
        prompt_unlock
        remove_value authentik-bootstrap-token
        remove_value authentik-bootstrap-password
        echo "Authentik bootstrap credentials removed. Run nas-secrets activate to remove runtime artifacts."
      }

      command_set_hf_token() {
        acquire_lock
        prompt_unlock
        ensure_group
        local token
        read -r -s -p "Hugging Face read token: " token
        echo
        [[ "$token" =~ ^hf_[A-Za-z0-9]{20,}$ ]] || { echo "Token format is invalid." >&2; exit 1; }
        store_value huggingface-token "$token"
        unset token
        echo "Token stored. Run nas-secrets activate to export it."
      }

      command_clear_hf_token() {
        acquire_lock
        prompt_unlock
        remove_value huggingface-token
        echo "Hugging Face token removed. Run nas-secrets activate."
      }

      command_set_ai_provider_key_stdin() {
        local provider="''${2:-}" token
        validate_ai_provider_id "$provider"
        acquire_lock
        password_from_stdin=true
        prompt_unlock
        ensure_group
        IFS= read -r token || { echo "Unable to read the AI provider API key from standard input." >&2; exit 1; }
        if IFS= read -r _; then
          echo "Unexpected extra input while setting the AI provider API key." >&2
          exit 1
        fi
        require_secret_atom "$token" "AI provider API key" 8 4096
        store_value "ai-provider-$provider" "$token"
        stage_ai_provider_runtime_key "$provider" "$token"
        unset token
        echo "AI provider API key stored and staged."
      }

      command_clear_ai_provider_key_stdin() {
        local provider="''${2:-}"
        validate_ai_provider_id "$provider"
        acquire_lock
        password_from_stdin=true
        prompt_unlock
        if IFS= read -r _; then
          echo "Unexpected extra input while clearing the AI provider API key." >&2
          exit 1
        fi
        remove_value "ai-provider-$provider"
        remove_ai_provider_runtime_key "$provider"
        echo "AI provider API key removed."
      }

      command_show_ai_provider_key() {
        local provider="''${2:-}"
        validate_ai_provider_id "$provider"
        acquire_lock
        prompt_unlock
        if has_secret "ai-provider-$provider"; then
          get_secret "ai-provider-$provider"
        fi
      }

      command_show_ai_provider_key_stdin() {
        local provider="''${2:-}"
        validate_ai_provider_id "$provider"
        acquire_lock
        password_from_stdin=true
        prompt_unlock
        if IFS= read -r _; then
          echo "Unexpected extra input while showing the AI provider API key." >&2
          exit 1
        fi
        if has_secret "ai-provider-$provider"; then
          get_secret "ai-provider-$provider"
        fi
      }

      command_show_ai_api_key() {
        prompt_unlock
        get_secret llama-swap-api-key
        echo
      }

      command_show_ntfy_password() {
        prompt_unlock
        get_secret ntfy-admin-password
        echo
      }

      command_show_zfs_key() {
        prompt_unlock
        get_secret zfs-dataset-key
        echo
      }

      command_show_zfs_key_stdin() {
        password_from_stdin=true
        prompt_unlock
        if IFS= read -r _; then
          echo "Unexpected extra input while showing the ZFS dataset key." >&2
          exit 1
        fi
        get_secret zfs-dataset-key
      }

      command_show_authentik_bootstrap() {
        prompt_unlock
        printf 'Username: akadmin\nPassword: %s\n' "$(get_secret authentik-bootstrap-password)"
      }

      enter_operation_coordinator() {
        case "''${1:-}" in
          init|adopt-authentik-bootstrap-stdin|activate|activate-stdin|activate-setup-stdin|stop|set-authentik-token|set-authentik-token-stdin|retire-authentik-bootstrap-stdin|set-hf-token|clear-hf-token|set-ai-provider-key-stdin|clear-ai-provider-key-stdin|show-ai-provider-key|show-ai-provider-key-stdin)
            local runner="''${NAS_OPERATION_RUNNER:-/run/current-system/sw/bin/nas-operation-run}"
            [[ -x "$runner" ]] || {
              echo "NAS operation coordinator is unavailable: $runner" >&2
              exit 1
            }
            if [[ -n "''${NAS_OPERATION_COORDINATION_TOKEN:-}" ]]; then
              "$runner" --validate-current --class secrets --class runtime || exit $?
              return 0
            fi
            exec "$runner" --action "nas-secrets:''${1}" --class secrets --class runtime -- "$0" "$@"
            ;;
        esac
      }

      enter_operation_coordinator "$@"

      case "''${1:-}" in
        init) command_init ;;
        adopt-authentik-bootstrap-stdin) command_adopt_authentik_bootstrap_stdin ;;
        activate) command_activate ;;
        activate-stdin)
          password_from_stdin=true
          command_activate
          ;;
        activate-setup-stdin)
          password_from_stdin=true
          command_activate true
          ;;
        status) command_status ;;
        stop) command_stop ;;
        set-authentik-token) command_set_authentik_token ;;
        set-authentik-token-stdin) command_set_authentik_token_stdin ;;
        retire-authentik-bootstrap-stdin) command_retire_authentik_bootstrap_stdin ;;
        check-authentik-token) command_check_authentik_token ;;
        set-hf-token) command_set_hf_token ;;
        clear-hf-token) command_clear_hf_token ;;
        set-ai-provider-key-stdin) command_set_ai_provider_key_stdin "$@" ;;
        clear-ai-provider-key-stdin) command_clear_ai_provider_key_stdin "$@" ;;
        show-ai-provider-key) command_show_ai_provider_key "$@" ;;
        show-ai-provider-key-stdin) command_show_ai_provider_key_stdin "$@" ;;
        show-ai-api-key) command_show_ai_api_key ;;
        show-ntfy-password) command_show_ntfy_password ;;
        show-zfs-key) command_show_zfs_key ;;
        show-zfs-key-stdin) command_show_zfs_key_stdin ;;
        show-authentik-bootstrap) command_show_authentik_bootstrap ;;
        *)
          echo "Usage: nas-secrets {init|adopt-authentik-bootstrap-stdin|activate|activate-stdin|status|stop|set-authentik-token|set-authentik-token-stdin|retire-authentik-bootstrap-stdin|check-authentik-token|set-hf-token|clear-hf-token|set-ai-provider-key-stdin PROVIDER|clear-ai-provider-key-stdin PROVIDER|show-ai-provider-key PROVIDER|show-ai-provider-key-stdin PROVIDER|show-ai-api-key|show-ntfy-password|show-zfs-key|show-zfs-key-stdin|show-authentik-bootstrap}" >&2
          exit 2
          ;;
      esac
    '';
  };
in
{
  inherit nasSecrets;
}
