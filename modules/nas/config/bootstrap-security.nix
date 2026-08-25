{ lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
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
        --create-home \
        --shell /run/current-system/sw/bin/nologin \
        nas-bootstrap || {
          rc=$?
          [[ "$rc" -eq 9 ]] || exit "$rc"
        }
    fi

    # The bootstrap Linux identity is a lifecycle marker/service identity only.
    # Network setup authentication is owned by the disposable Authentik/KDBX
    # trust domain, so this account must never accept a reusable password login.
    ${pkgs.shadow}/bin/passwd --lock nas-bootstrap >/dev/null
    ${pkgs.shadow}/bin/usermod \
      --shell /run/current-system/sw/bin/nologin \
      --append --groups wheel,nas-administrators,nas-operations \
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

    # The permanent runtime has already been selected: bootstrap authority must
    # not be recreated after this boundary.
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

    # These credentials belong only to the disposable bootstrap trust domain.
    # Every permanent secret is generated again after the runtime switch. The
    # human bootstrap password is installation-unique; there is deliberately no
    # fleet-wide/default password that can claim a newly installed appliance.
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

    # The console/KVM is the initial ownership channel. Never emit this value to
    # stdout/stderr or the journal; write it directly to the local console.
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
in
{
  # Replace the fixed-password bootstrap Linux account with a locked service
  # identity. The authenticated web setup path is independent of PAM/Cockpit.
  systemd.services.nas-bootstrap-administrator.serviceConfig.ExecStart = lib.mkForce bootstrapAdministrator;

  # Keep one temporary KDBX as the bootstrap secret authority. It is deliberately
  # separate from the user-password-protected permanent NAS.kdbx and is deleted
  # when first-run retires /var/lib/nas-bootstrap.
  systemd.services.nas-bootstrap-authentik-secrets = {
    path = [ pkgs.coreutils pkgs.gnugrep pkgs.keepassxc pkgs.openssl ];
    serviceConfig.ExecStart = lib.mkForce bootstrapSecrets;
  };

  # The API calls the hardened finite job directly. No PATH interception or
  # alternate nas-setup implementation is needed.
  systemd.services.nas-first-run-api.environment.NAS_FIRST_START_JOB =
    "${nasPythonApplication}/bin/nas-first-start-job";
}
