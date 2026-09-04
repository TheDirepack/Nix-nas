args:
let
  inherit (args)
    cfg
    lib
    nasSecrets
    pkgs
    zfsKeyFingerprintProperty
    zfsKeyPath
  ;
  zfsCockpitWrapper = pkgs.writeShellApplication {
    name = "zfs";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.openssl
    ];
    text = ''
      set -euo pipefail
      real_zfs=${pkgs.zfs}/bin/zfs

      if [[ "''${1:-}" != "rollback" ]] || (( $# < 2 )); then
        exec "$real_zfs" "$@"
      fi

      source_snapshot="''${!#}"
      if "$real_zfs" "$@"; then
        :
      else
        rollback_status=$?
        exit "$rollback_status"
      fi

      if [[ "$source_snapshot" != *@* ]]; then
        echo "WARNING: rollback completed, but no post-restore marker was created because the source snapshot was not identifiable." >&2
        exit 0
      fi

      dataset="''${source_snapshot%@*}"
      source_name="''${source_snapshot#*@}"
      safe_source="$(printf '%s' "$source_name" | tr -cs 'A-Za-z0-9._-' '-' | cut -c1-80)"
      if ! timestamp="$(date -u +%Y%m%dT%H%M%S%NZ)"; then
        echo "WARNING: rollback completed, but generating the marker timestamp failed." >&2
        exit 0
      fi
      if ! suffix="$(openssl rand -hex 3)"; then
        echo "WARNING: rollback completed, but generating the marker suffix failed." >&2
        exit 0
      fi
      marker="''${dataset}@restored-''${safe_source}-''${timestamp}-''${suffix}"

      if ! "$real_zfs" snapshot \
        -o "org.nixos:restore-source=$source_snapshot" \
        "$marker"; then
        echo "WARNING: rollback completed successfully, but creating post-restore marker '$marker' failed." >&2
        exit 0
      fi

      printf 'Created post-restore marker: %s\n' "$marker"
    '';
  };

  # Work around NixOS/nixpkgs#530137 with Node 22.
  cockpitZfsBuildPackages = pkgs.buildPackages // {
    yarn-berry = pkgs.buildPackages.yarn-berry.override {
      nodejs = pkgs.buildPackages.nodejs_22;
    };
  };
  cockpitZfsBase = pkgs.cockpit-zfs.override {
    nodejs = pkgs.nodejs_22;
    yarn-berry = pkgs.yarn-berry.override { nodejs = pkgs.nodejs_22; };
    buildPackages = cockpitZfsBuildPackages;
  };
  cockpitZfsPlugin = cockpitZfsBase.overrideAttrs (old: {
    passthru = (old.passthru or { }) // {
      # Override only the rollback command with the checkpoint wrapper.
      cockpitPath =
        [ zfsCockpitWrapper ]
        ++ lib.filter (package: package != pkgs.zfs) (old.passthru.cockpitPath or [ ]);
    };
  });

  nasZfsMountCheck = pkgs.writeShellApplication {
    name = "nas-zfs-mount-check";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.findutils
      pkgs.jq
      pkgs.util-linux
    ];
    text = ''
      set -euo pipefail
      expected_root=${lib.escapeShellArg cfg.zfsRoot}
      expected_dataset=${lib.escapeShellArg cfg.zfsDataset}
      real_zfs=${pkgs.zfs}/bin/zfs
      ${lib.optionalString cfg.zfsEncryption.enable ''
      expected_key_file=${lib.escapeShellArg zfsKeyPath}
      fingerprint_property=${lib.escapeShellArg zfsKeyFingerprintProperty}
      expected_encryption=auto
      if [[ -s /var/lib/nas-setup/state.json ]]; then
        expected_encryption="$(${pkgs.jq}/bin/jq -er '.storage.encrypted | if . then "true" else "false" end' /var/lib/nas-setup/state.json)"
      fi
      ''}

      mountpoint --quiet -- "$expected_root" || {
        echo "$expected_root is not a mount point" >&2
        exit 1
      }

      mount_rows="$(findmnt --raw --noheadings --output SOURCE,FSTYPE,TARGET --target "$expected_root")"
      expected_mount_visible=false
      while read -r actual_source actual_type actual_target; do
        if [[ "$actual_source" == "$expected_dataset" && "$actual_type" == "zfs" && "$actual_target" == "$expected_root" ]]; then
          expected_mount_visible=true
          break
        fi
      done <<< "$mount_rows"
      [[ "$expected_mount_visible" == true ]] || {
        echo "$expected_root is not visibly backed by ZFS dataset '$expected_dataset': $mount_rows" >&2
        exit 1
      }

      configured_mountpoint="$("$real_zfs" get -H -o value mountpoint "$expected_dataset")"
      mounted="$("$real_zfs" get -H -o value mounted "$expected_dataset")"
      [[ "$configured_mountpoint" == "$expected_root" && "$mounted" == "yes" ]] || {
        echo "$expected_dataset must have mountpoint=$expected_root and mounted=yes" >&2
        exit 1
      }

      ${lib.optionalString cfg.zfsEncryption.enable ''
      encryption_algorithm="$($real_zfs get -H -o value encryption "$expected_dataset")"
      actual_encryption=true
      [[ "$encryption_algorithm" == off ]] && actual_encryption=false
      if [[ "$expected_encryption" != auto && "$actual_encryption" != "$expected_encryption" ]]; then
        echo "$expected_dataset encryption state does not match the reviewed first-start choice" >&2
        exit 1
      fi
      if [[ "$actual_encryption" == true ]]; then
      encryptionroot="$($real_zfs get -H -o value encryptionroot "$expected_dataset")"
      keyformat="$($real_zfs get -H -o value keyformat "$expected_dataset")"
      keylocation="$($real_zfs get -H -o value keylocation "$expected_dataset")"
      keystatus="$($real_zfs get -H -o value keystatus "$expected_dataset")"
      [[ "$encryptionroot" == "$expected_dataset" ]] || {
        echo "$expected_dataset must be its own ZFS encryption root, got '$encryptionroot'" >&2
        exit 1
      }
      [[ "$keyformat" == "hex" ]] || {
        echo "$expected_dataset must use keyformat=hex, got '$keyformat'" >&2
        exit 1
      }
      [[ "$keylocation" == "file://${zfsKeyPath}" ]] || {
        echo "$expected_dataset must use keylocation=file://${zfsKeyPath}, got '$keylocation'" >&2
        exit 1
      }
      [[ "$keystatus" == "available" ]] || {
        echo "$expected_dataset encryption key is not loaded" >&2
        exit 1
      }
      stored_fingerprint="$($real_zfs get -H -o value "$fingerprint_property" "$expected_dataset")"
      staged_fingerprint="$(sha256sum "$expected_key_file" | cut -d ' ' -f1)"
      [[ "$stored_fingerprint" == "$staged_fingerprint" ]] || {
        echo "$expected_dataset does not match the KeePassXC-staged ZFS key fingerprint" >&2
        exit 1
      }
      fi
      ''}
    '';
  };

  nasZfsUnlock = pkgs.writeShellApplication {
    name = "nas-zfs-unlock";
    runtimeInputs = [ pkgs.coreutils pkgs.util-linux pkgs.zfs ];
    text = ''
      set -euo pipefail
      dataset=${lib.escapeShellArg cfg.zfsDataset}
      root=${lib.escapeShellArg cfg.zfsRoot}
      key_file=${lib.escapeShellArg zfsKeyPath}
      real_zfs=${pkgs.zfs}/bin/zfs
      encryption_enabled=${if cfg.zfsEncryption.enable then "1" else "0"}

      if [[ "$encryption_enabled" != "1" ]]; then
        echo "nas.zfsEncryption.enable is false; no managed ZFS key is configured." >&2
        exit 1
      fi
      if [[ "$($real_zfs get -H -o value encryption "$dataset")" == off ]]; then
        if [[ "$($real_zfs get -H -o value mounted "$dataset")" != yes ]]; then
          $real_zfs mount "$dataset"
        fi
        mountpoint --quiet -- "$root"
        exit 0
      fi
      [[ -r "$key_file" ]] || { echo "Missing staged ZFS key: $key_file" >&2; exit 1; }
      identity="$(stat -c '%a:%U:%G' "$key_file")"
      [[ "$identity" == "400:root:root" ]] || {
        echo "ZFS key has unsafe mode or ownership: $identity" >&2
        exit 1
      }
      [[ "$($real_zfs get -H -o value encryptionroot "$dataset")" == "$dataset" ]] || {
        echo "$dataset is not its own encryption root" >&2
        exit 1
      }
      [[ "$($real_zfs get -H -o value keyformat "$dataset")" == "hex" ]] || {
        echo "$dataset does not use keyformat=hex" >&2
        exit 1
      }
      stored_fingerprint="$($real_zfs get -H -o value ${lib.escapeShellArg zfsKeyFingerprintProperty} "$dataset")"
      staged_fingerprint="$(sha256sum "$key_file" | cut -d ' ' -f1)"
      [[ "$stored_fingerprint" == "$staged_fingerprint" ]] || {
        echo "$dataset does not match the KeePassXC-staged key fingerprint" >&2
        exit 1
      }
      if [[ "$($real_zfs get -H -o value keystatus "$dataset")" != "available" ]]; then
        $real_zfs load-key -L "file://$key_file" "$dataset"
      fi
      if [[ "$($real_zfs get -H -o value mounted "$dataset")" != "yes" ]]; then
        $real_zfs mount "$dataset"
      fi
      mountpoint --quiet -- "$root"
    '';
  };

  nasZfsLock = pkgs.writeShellApplication {
    name = "nas-zfs-lock";
    runtimeInputs = [ pkgs.coreutils pkgs.systemd pkgs.zfs ];
    text = ''
      export PATH=/run/wrappers/bin:$PATH
      set -euo pipefail
      dataset=${lib.escapeShellArg cfg.zfsDataset}
      if [[ "$(${pkgs.zfs}/bin/zfs get -H -o value encryption "$dataset")" == off ]]; then
        echo "$dataset is not encrypted; there is no ZFS key to unload." >&2
        exit 1
      fi
      sudo systemctl stop nas-protected-services.target
      zfs_retry() {
        local label=$1
        shift
        local attempt output
        for attempt in $(seq 1 120); do
          if output="$(sudo ${pkgs.zfs}/bin/zfs "$@" 2>&1)"; then
            return 0
          fi
          if [[ "$attempt" -eq 120 ]]; then
            printf '%s\n' "$output" >&2
            echo "Timed out waiting to $label for $dataset after protected services stopped." >&2
            return 1
          fi
          sleep 1
        done
      }
      if [[ "$(${pkgs.zfs}/bin/zfs get -H -o value mounted "$dataset")" == "yes" ]]; then
        zfs_retry unmount unmount "$dataset"
      fi
      if [[ "$(${pkgs.zfs}/bin/zfs get -H -o value keystatus "$dataset")" == "available" ]]; then
        zfs_retry unload-key unload-key -r "$dataset"
      fi
      sudo rm -f -- ${lib.escapeShellArg zfsKeyPath}
      echo "ZFS dataset unmounted and key unloaded. Run nas-secrets activate to unlock it again."
    '';
  };

  nasZfsCreateEncryptedDataset = pkgs.writeShellApplication {
    name = "nas-zfs-create-encrypted-dataset";
    runtimeInputs = [ pkgs.coreutils nasSecrets pkgs.zfs ];
    text = ''
      export PATH=/run/wrappers/bin:$PATH
      set -euo pipefail
      dataset=${lib.escapeShellArg cfg.zfsDataset}
      pool=${lib.escapeShellArg cfg.zfsPool}
      root=${lib.escapeShellArg cfg.zfsRoot}
      algorithm=${lib.escapeShellArg cfg.zfsEncryption.algorithm}
      final_keylocation=${lib.escapeShellArg "file://${zfsKeyPath}"}
      secret_reader=${lib.escapeShellArg "${nasSecrets}/bin/nas-secrets"}
      zfs=${lib.escapeShellArg "${pkgs.zfs}/bin/zfs"}
      zpool=${lib.escapeShellArg "${pkgs.zfs}/bin/zpool"}
      encryption_enabled=${if cfg.zfsEncryption.enable then "1" else "0"}
      created_dataset=false
      bootstrap_committed=false

      if [[ "$encryption_enabled" != "1" ]]; then
        echo "Enable nas.zfsEncryption.enable before creating the managed encryption root." >&2
        exit 1
      fi
      actor="$(id -un)"
      [[ " $(id -nG) " == *" nas-administrators "* || ( "$actor" == root && "''${NAS_SETUP_ALLOW_ROOT:-}" == 1 ) ]] || {
        echo "Run this as the wizard-created Linux administrator; Cockpit may execute it as an explicitly authorized root setup operation." >&2
        exit 1
      }
      sudo -v
      sudo "$zpool" list -H "$pool" >/dev/null
      if sudo "$zfs" list -H "$dataset" >/dev/null 2>&1; then
        echo "$dataset already exists; refusing to modify or recreate it." >&2
        exit 1
      fi

      key="$($secret_reader show-zfs-key-stdin)" || {
        echo "The KeePassXC ZFS key is missing. Run nas-secrets init first." >&2
        exit 1
      }
      [[ "$key" =~ ^[0-9a-fA-F]{64}$ ]] || {
        echo "The stored ZFS key is not a 32-byte hexadecimal key." >&2
        exit 1
      }
      local_tmp="$(mktemp)"
      root_tmp="$(sudo mktemp /run/nas-zfs-bootstrap.XXXXXX)"
      cleanup() {
        local rc=$? cleanup_failed=false
        trap - EXIT HUP INT TERM
        set +e
        rm -f -- "$local_tmp" || cleanup_failed=true
        if [[ "$rc" -ne 0 && "$created_dataset" == true && "$bootstrap_committed" != true ]]; then
          # The dataset was created by this invocation and canmount=off kept it
          # inaccessible to ordinary writers. Remove it rather than leaving an
          # encryption root whose configured keylocation points at a transient file.
          if sudo "$zfs" list -H "$dataset" >/dev/null 2>&1; then
            if sudo "$zfs" destroy -r "$dataset" >/dev/null 2>&1; then
              created_dataset=false
            else
              echo "CRITICAL: encrypted dataset bootstrap failed and automatic cleanup could not destroy $dataset." >&2
              echo "The key remains in KeePassXC. Recover or destroy the dataset before retrying setup." >&2
              cleanup_failed=true
            fi
          fi
        fi
        sudo rm -f -- "$root_tmp" || cleanup_failed=true
        unset key
        if $cleanup_failed; then
          exit 125
        fi
        exit "$rc"
      }
      trap cleanup EXIT
      trap 'exit 129' HUP
      trap 'exit 130' INT
      trap 'exit 143' TERM
      chmod 0600 "$local_tmp"
      printf '%s' "$key" > "$local_tmp"
      sudo install -m 0400 -o root -g root "$local_tmp" "$root_tmp"
      fingerprint="$(sha256sum "$local_tmp" | cut -d ' ' -f1)"

      sudo "$zfs" create -p \
        -o encryption="$algorithm" \
        -o keyformat=hex \
        -o keylocation="file://$root_tmp" \
        -o canmount=off \
        -o mountpoint="$root" \
        "$dataset"
      created_dataset=true

      # Fault-injection points are disabled unless explicitly enabled by the VM
      # security test. They make every post-create transition reproducibly testable
      # without weakening normal execution.
      bootstrap_fault() {
        local step=$1
        if [[ "''${NAS_TEST_FAULT_INJECTION:-}" == 1 && "''${NAS_TEST_ZFS_BOOTSTRAP_FAIL_AFTER:-}" == "$step" ]]; then
          echo "Injected ZFS bootstrap failure after $step" >&2
          return 97
        fi
      }

      bootstrap_fault create
      sudo "$zfs" set keylocation="$final_keylocation" "$dataset"
      bootstrap_fault keylocation
      sudo "$zfs" set ${zfsKeyFingerprintProperty}="$fingerprint" "$dataset"
      bootstrap_fault fingerprint
      sudo "$zfs" set canmount=on "$dataset"
      bootstrap_fault canmount
      if [[ "$(sudo "$zfs" get -H -o value mounted "$dataset")" == "yes" ]]; then
        sudo "$zfs" unmount "$dataset"
      fi
      bootstrap_fault unmount
      sudo "$zfs" unload-key "$dataset"
      bootstrap_fault unload-key

      bootstrap_committed=true
      echo "Created $dataset as a locked ZFS encryption root. Run nas-secrets activate to stage the key, unlock it, and start the NAS services."
    '';
  };

  nasZfsExportRecoveryKey = pkgs.writeShellApplication {
    name = "nas-zfs-export-recovery-key";
    runtimeInputs = [ pkgs.coreutils nasSecrets ];
    text = ''
      export PATH=/run/wrappers/bin:$PATH
      set -euo pipefail
      [[ $# -eq 1 ]] || { echo "Usage: nas-zfs-export-recovery-key /absolute/output-file" >&2; exit 2; }
      output="$1"
      [[ "$output" == /* ]] || { echo "The output path must be absolute." >&2; exit 2; }
      [[ " $(id -nG) " == *" nas-administrators "* ]] || {
        echo "Run this as the wizard-created Linux administrator; the KeePassXC database password will be requested interactively." >&2
        exit 1
      }
      if [[ -t 0 ]]; then
        key="$(${nasSecrets}/bin/nas-secrets show-zfs-key)"
      else
        key="$(${nasSecrets}/bin/nas-secrets show-zfs-key-stdin)"
      fi || {
        echo "The KeePassXC ZFS key is missing." >&2
        exit 1
      }
      [[ "$key" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "The stored ZFS key has an unexpected format." >&2; exit 1; }
      tmp="$(mktemp)"
      trap 'rm -f -- "$tmp"; unset key' EXIT
      chmod 0600 "$tmp"
      printf '%s' "$key" > "$tmp"
      sudo install -m 0400 -o root -g root "$tmp" "$output"
      echo "Wrote a root-only recovery key to $output. Store it offline and test it before relying on encryption."
    '';
  };
in
{
  inherit
    zfsCockpitWrapper
    cockpitZfsPlugin
    nasZfsMountCheck
    nasZfsUnlock
    nasZfsLock
    nasZfsCreateEncryptedDataset
    nasZfsExportRecoveryKey
  ;
}
