{ lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikApiTokenFile
    authentikEnvironmentFile
    authentikRuntimeApiTokenFile
    authentikRuntimeEnvironmentFile
    bootstrapAuthentikDataDir
    bootstrapRuntimeRoot
    bootstrapSecretsDir
    nasPythonApplication
  ;

  bootstrapDatabase = "${bootstrapSecretsDir}/NAS.kdbx";
  bootstrapPasswordFile = "${bootstrapRuntimeRoot}/kdbx-password";
  bootstrapGroup = "bootstrap";

  bootstrapAdministrator = pkgs.writeShellScript "nas-bootstrap-administrator-secure" ''
    set -euo pipefail
    if ! ${pkgs.glibc.bin}/bin/getent passwd nas-bootstrap >/dev/null 2>&1; then
      ${pkgs.shadow}/bin/useradd \
        --no-create-home \
        --shell /run/current-system/sw/bin/nologin \
        nas-bootstrap || {
          rc=$?
          [[ "$rc" -eq 9 ]] || exit "$rc"
        }
    fi

    # The standalone setup UI authenticates through bootstrap Authentik, not
    # this local account. Keep the Linux bootstrap principal locked/nologin and
    # give it only the wheel role needed to remain the temporary host admin.
    ${pkgs.shadow}/bin/passwd --lock nas-bootstrap >/dev/null
    ${pkgs.shadow}/bin/usermod \
      --shell /run/current-system/sw/bin/nologin \
      --groups wheel \
      nas-bootstrap
  '';

  bootstrapSecrets = pkgs.writeShellScript "nas-bootstrap-kdbx-secrets" ''
    set -euo pipefail
    umask 0077

    db=${lib.escapeShellArg bootstrapDatabase}
    password_file=${lib.escapeShellArg bootstrapPasswordFile}
    secret_dir=${lib.escapeShellArg bootstrapSecretsDir}
    authentik_dir=${lib.escapeShellArg bootstrapAuthentikDataDir}
    group=${lib.escapeShellArg bootstrapGroup}

    if [[ -e /var/lib/nas-setup/operational-runtime-select || -e /var/lib/nas-setup/state.json ]]; then
      exit 0
    fi

    ${pkgs.coreutils}/bin/install -d -m 0700 -o root -g root "$secret_dir"
    ${pkgs.coreutils}/bin/install -d -m 0750 -o authentik -g authentik "$authentik_dir"

    if [[ -L "$secret_dir" || -L "$authentik_dir" || -L "$db" || -L "$password_file" ]]; then
      echo "Refusing symlinked bootstrap trust-store paths." >&2
      exit 70
    fi

    db_exists=false
    password_exists=false
    [[ -f "$db" ]] && db_exists=true
    [[ -f "$password_file" ]] && password_exists=true
    if [[ "$db_exists" != "$password_exists" ]]; then
      echo "Bootstrap KDBX/password state is incomplete; refusing to overwrite it." >&2
      exit 71
    fi

    if ! $db_exists; then
      password="$(${pkgs.openssl}/bin/openssl rand -hex 32)"
      temporary_password="$(${pkgs.coreutils}/bin/mktemp "$bootstrapRuntimeRoot/.kdbx-password.XXXXXX")"
      trap '${pkgs.coreutils}/bin/rm -f -- "$temporary_password"' EXIT
      printf '%s' "$password" > "$temporary_password"
      ${pkgs.coreutils}/bin/install -m 0400 -o root -g root "$temporary_password" "$password_file"
      printf '%s\n%s\n' "$password" "$password" \
        | ${pkgs.keepassxc}/bin/keepassxc-cli db-create --quiet -p "$db" >/dev/null
      ${pkgs.coreutils}/bin/chown root:root "$db"
      ${pkgs.coreutils}/bin/chmod 0600 "$db"
      unset password
      ${pkgs.coreutils}/bin/rm -f -- "$temporary_password"
      trap - EXIT
    fi

    IFS= read -r password < "$password_file"
    if [[ ! "$password" =~ ^[0-9a-f]{64}$ ]]; then
      echo "Bootstrap KDBX password file is malformed." >&2
      exit 72
    fi
    if ! printf '%s\n' "$password" \
      | ${pkgs.keepassxc}/bin/keepassxc-cli db-info --quiet "$db" >/dev/null 2>&1; then
      echo "Bootstrap KDBX cannot be unlocked; refusing to recreate it." >&2
      exit 73
    fi

    kp_ls() {
      printf '%s\n' "$password" \
        | ${pkgs.keepassxc}/bin/keepassxc-cli ls --quiet --flatten "$db" "$group" 2>/dev/null
    }
    if ! printf '%s\n' "$password" \
      | ${pkgs.keepassxc}/bin/keepassxc-cli ls --quiet "$db" "$group" >/dev/null 2>&1; then
      printf '%s\n' "$password" \
        | ${pkgs.keepassxc}/bin/keepassxc-cli mkdir --quiet "$db" "$group" >/dev/null
    fi

    ensure_entry() {
      local key="$1" value="$2"
      if kp_ls | ${pkgs.gnugrep}/bin/grep -Fxq -- "$key"; then
        return 0
      fi
      printf '%s\n%s\n' "$password" "$value" \
        | ${pkgs.keepassxc}/bin/keepassxc-cli add --quiet -p "$db" "$group/$key" >/dev/null
    }

    ensure_entry authentik-secret-key "$(${pkgs.openssl}/bin/openssl rand -hex 64)"
    ensure_entry authentik-bootstrap-token "$(${pkgs.openssl}/bin/openssl rand -hex 32)"
    ensure_entry authentik-bootstrap-password "$(${pkgs.openssl}/bin/openssl rand -hex 16)"

    get_entry() {
      printf '%s\n' "$password" \
        | ${pkgs.keepassxc}/bin/keepassxc-cli show --quiet --show-protected \
            -a Password "$db" "$group/$1"
    }

    authentik_secret="$(get_entry authentik-secret-key)"
    bootstrap_token="$(get_entry authentik-bootstrap-token)"
    bootstrap_password="$(get_entry authentik-bootstrap-password)"

    [[ "$authentik_secret" =~ ^[0-9a-f]{128}$ ]] || exit 74
    [[ "$bootstrap_token" =~ ^[0-9a-f]{64}$ ]] || exit 74
    [[ "$bootstrap_password" =~ ^[0-9a-f]{32}$ ]] || exit 74

    environment="$authentik_dir/environment"
    api_token="$authentik_dir/api-token"
    temporary_environment="$(${pkgs.coreutils}/bin/mktemp "$authentik_dir/.environment.XXXXXX")"
    temporary_token="$(${pkgs.coreutils}/bin/mktemp "$authentik_dir/.api-token.XXXXXX")"
    trap '${pkgs.coreutils}/bin/rm -f -- "$temporary_environment" "$temporary_token"' EXIT
    {
      printf 'AUTHENTIK_SECRET_KEY=%s\n' "$authentik_secret"
      printf 'AUTHENTIK_BOOTSTRAP_TOKEN=%s\n' "$bootstrap_token"
      printf 'AUTHENTIK_BOOTSTRAP_PASSWORD=%s\n' "$bootstrap_password"
      printf 'AUTHENTIK_BOOTSTRAP_EMAIL=%s\n' 'admin@localhost'
    } > "$temporary_environment"
    printf '%s' "$bootstrap_token" > "$temporary_token"
    ${pkgs.coreutils}/bin/install -m 0640 -o root -g authentik "$temporary_environment" "$environment"
    ${pkgs.coreutils}/bin/install -m 0400 -o root -g root "$temporary_token" "$api_token"

    if [[ -w /dev/console ]]; then
      printf '\nNixOS NAS first-run setup\n  user: akadmin\n  password: %s\n\n' "$bootstrap_password" > /dev/console
    else
      echo "First-run credential could not be displayed because /dev/console is unavailable." >&2
      exit 75
    fi

    unset password authentik_secret bootstrap_token bootstrap_password
    ${pkgs.coreutils}/bin/rm -f -- "$temporary_environment" "$temporary_token"
    trap - EXIT
  '';

  runtimeSelector = pkgs.writeShellScript "nas-bootstrap-runtime-select-secure" ''
    set -euo pipefail
    umask 0077

    if [[ -e /var/lib/nas-setup/operational-runtime-select || -e /var/lib/nas-setup/state.json ]]; then
      target=/var/lib/nas-operational
      environment=${lib.escapeShellArg authentikEnvironmentFile}
      api_token=${lib.escapeShellArg authentikApiTokenFile}
    else
      target=${lib.escapeShellArg bootstrapRuntimeRoot}
      environment="$target/authentik/environment"
      api_token="$target/authentik/api-token"
    fi

    if [[ -L "$target" ]]; then
      echo "Refusing symlinked identity runtime root: $target" >&2
      exit 76
    fi
    ${pkgs.coreutils}/bin/install -d -m 0700 -o root -g root "$target"

    ensure_runtime_dir() {
      local path="$1" mode="$2" owner="$3" group="$4"
      if [[ -L "$path" ]]; then
        echo "Refusing symlinked identity runtime directory: $path" >&2
        exit 76
      fi
      ${pkgs.coreutils}/bin/install -d -m "$mode" -o "$owner" -g "$group" "$path"
    }
    ensure_runtime_dir "$target/authentik" 0750 authentik authentik
    ensure_runtime_dir "$target/postgresql" 0700 postgres postgres
    ensure_runtime_dir "$target/nas-secrets" 0770 root nas-administrators

    link_authority() {
      local name="$1" source="$target/$1" destination="/var/lib/$1"
      if [[ -L "$destination" ]]; then
        current="$(${pkgs.coreutils}/bin/readlink -- "$destination")"
        if [[ "$current" == "$source" ]]; then
          return 0
        fi
        ${pkgs.coreutils}/bin/rm -f -- "$destination"
      elif [[ -e "$destination" ]]; then
        if [[ ! -d "$destination" ]]; then
          echo "Refusing to replace non-directory authority path: $destination" >&2
          exit 77
        fi
        if [[ -n "$(${pkgs.findutils}/bin/find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
          echo "Refusing to replace non-empty authority directory: $destination" >&2
          exit 77
        fi
        ${pkgs.coreutils}/bin/rmdir -- "$destination"
      fi
      ${pkgs.coreutils}/bin/ln -s -- "$source" "$destination"
    }

    link_authority authentik
    link_authority postgresql
    link_authority nas-secrets

    ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g authentik /run/nas-authentik
    for spec in \
      "${lib.escapeShellArg authentikRuntimeEnvironmentFile}:$environment" \
      "${lib.escapeShellArg authentikRuntimeApiTokenFile}:$api_token"; do
      destination="''${spec%%:*}"
      source="''${spec#*:}"
      if [[ -e "$destination" && ! -L "$destination" ]]; then
        echo "Refusing to replace non-symlink runtime credential path: $destination" >&2
        exit 78
      fi
      ${pkgs.coreutils}/bin/rm -f -- "$destination"
      ${pkgs.coreutils}/bin/ln -s -- "$source" "$destination"
    done
  '';
in
{
  systemd.services.nas-bootstrap-administrator.serviceConfig.ExecStart = lib.mkOverride 40 bootstrapAdministrator;

  systemd.services.nas-bootstrap-authentik-secrets = {
    path = [ pkgs.coreutils pkgs.gnugrep pkgs.keepassxc pkgs.openssl ];
    serviceConfig.ExecStart = lib.mkOverride 40 bootstrapSecrets;
  };

  systemd.services.nas-bootstrap-runtime-select.serviceConfig.ExecStart =
    lib.mkOverride 40 runtimeSelector;

  # Authentik's embedded outpost is served by the main Authentik listener. The
  # legacy first-boot unit still carries an ExecStartPost for the deleted custom
  # proxy daemon on main, so clear that hook in the effective configuration.
  systemd.services.nas-identity-bootstrap = {
    description = lib.mkForce "Reconcile the Authentik setup application and embedded outpost";
    serviceConfig.ExecStartPost = lib.mkForce [ ];
  };

  systemd.services.nas-first-run-api.environment.NAS_FIRST_START_JOB =
    "${nasPythonApplication}/bin/nas-first-start-job";
}