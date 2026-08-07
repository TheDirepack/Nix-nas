args:
let
  inherit (args)
    nasFeatureControl
    nasIdentitySync
    nasSecrets
    nasSetup
    nasState
    nasUpdate
    pkgs
  ;

  nasDocumentation = pkgs.runCommand "nas-searchable-documentation" {
    nativeBuildInputs = [ pkgs.coreutils pkgs.gnused pkgs.mdbook ];
  } ''
    work="$TMPDIR/nas-docs"
    cp -R ${../../../docs} "$work"
    chmod -R u+w "$work"

    cp ${../../../README.md} "$work/src/reference/project-README.md"
    cp ${../../../SECURITY.md} "$work/src/reference/project-SECURITY.md"
    cp ${../../../docs/operator/recovery.md} "$work/src/reference/project-RECOVERY.md"
    cp ${../../../CHANGELOG.md} "$work/src/reference/project-CHANGELOG.md"

    emit_help() {
      title="$1"
      shift
      {
        printf '\n## %s\n\n```text\n' "$title"
        NO_COLOR=1 TERM=dumb timeout 15s "$@" --help 2>&1 || true
        printf '\n```\n'
      } >> "$work/src/reference/commands.md"
    }
    emit_help nas-identity-sync ${nasIdentitySync}/bin/nas-identity-sync
    emit_help nas-setup ${nasSetup}/bin/nas-setup
    emit_help nas-feature-control ${nasFeatureControl}/bin/nas-feature-control
    emit_help nas-state ${nasState}/bin/nas-state
    emit_help nas-secrets ${nasSecrets}/bin/nas-secrets
    emit_help nas-update ${nasUpdate}/bin/nas-update
    emit_help Syncthing ${pkgs.syncthing}/bin/syncthing
    emit_help keepassxc-cli ${pkgs.keepassxc}/bin/keepassxc-cli
    emit_help llama-swap ${pkgs.llama-swap}/bin/llama-swap
    emit_help Grafana ${pkgs.grafana}/bin/grafana
    emit_help ntfy ${pkgs.ntfy-sh}/bin/ntfy
    emit_help Telegraf ${pkgs.telegraf}/bin/telegraf
    emit_help smartctl ${pkgs.smartmontools}/bin/smartctl
    emit_help firewall-cmd ${pkgs.firewalld}/bin/firewall-cmd
    emit_help nmcli ${pkgs.networkmanager}/bin/nmcli
    emit_help Podman ${pkgs.podman}/bin/podman
    emit_help psql ${pkgs.postgresql}/bin/psql
    emit_help pg_dump ${pkgs.postgresql}/bin/pg_dump
    emit_help sqlite3 ${pkgs.sqlite}/bin/sqlite3
    emit_help Git ${pkgs.git}/bin/git
    emit_help Nix ${pkgs.nix}/bin/nix
    emit_help SSH ${pkgs.openssh}/bin/ssh

    emit_command() {
      title="$1"
      shift
      {
        printf '\n## %s\n\n```text\n' "$title"
        NO_COLOR=1 TERM=dumb timeout 15s "$@" 2>&1 || true
        printf '\n```\n'
      } >> "$work/src/reference/platform-command-help.md"
    }
    emit_command "Caddy command tree" ${pkgs.caddy}/bin/caddy help
    emit_command "Restic command tree" ${pkgs.restic}/bin/restic help
    emit_command "ZFS command tree" ${pkgs.zfs}/bin/zfs help
    emit_command "Zpool command tree" ${pkgs.zfs}/bin/zpool help
    emit_command "systemctl command help" ${pkgs.systemd}/bin/systemctl --help
    emit_command "VictoriaMetrics command help" ${pkgs.victoriametrics}/bin/victoria-metrics -help
    emit_command "vmalert command help" ${pkgs.victoriametrics}/bin/vmalert -help
    emit_command "Sanoid command help" ${pkgs.sanoid}/bin/sanoid --help
    emit_command "Syncoid command help" ${pkgs.sanoid}/bin/syncoid --help
    emit_command "virsh command tree" ${pkgs.libvirt}/bin/virsh help
    emit_command "NUT upsc help" ${pkgs.nut}/bin/upsc -h
    emit_command "NUT upscmd help" ${pkgs.nut}/bin/upscmd -h
    emit_command "journalctl help" ${pkgs.systemd}/bin/journalctl --help
    emit_command "systemd-analyze help" ${pkgs.systemd}/bin/systemd-analyze --help

    emit_version() {
      title="$1"
      shift
      printf '| `%s` | `%s` |\n' "$title" "$(NO_COLOR=1 TERM=dumb timeout 10s "$@" 2>&1 | head -n 1 | tr '|' '/' || true)" \
        >> "$work/src/reference/installed-versions.md"
    }
    {
      printf '# Installed component versions\n\n'
      printf 'Generated from the exact package closures used to build this NAS generation.\n\n'
      printf '| Component | Reported version |\n|---|---|\n'
    } > "$work/src/reference/installed-versions.md"
    emit_version CopyParty ${pkgs.copyparty}/bin/copyparty --version
    emit_version Syncthing ${pkgs.syncthing}/bin/syncthing --version
    emit_version KeePassXC ${pkgs.keepassxc}/bin/keepassxc-cli --version
    emit_version Caddy ${pkgs.caddy}/bin/caddy version
    emit_version VictoriaMetrics ${pkgs.victoriametrics}/bin/victoria-metrics --version
    emit_version vmalert ${pkgs.victoriametrics}/bin/vmalert --version
    emit_version Grafana ${pkgs.grafana}/bin/grafana --version
    emit_version Telegraf ${pkgs.telegraf}/bin/telegraf --version
    emit_version ntfy ${pkgs.ntfy-sh}/bin/ntfy --version
    emit_version Restic ${pkgs.restic}/bin/restic version
    emit_version ZFS ${pkgs.zfs}/bin/zfs version
    emit_version Sanoid ${pkgs.sanoid}/bin/sanoid --version
    emit_version Syncoid ${pkgs.sanoid}/bin/syncoid --version
    emit_version Podman ${pkgs.podman}/bin/podman --version
    emit_version Nix ${pkgs.nix}/bin/nix --version

    {
      printf '# CopyParty global help\n\nGenerated from the installed CopyParty package.\n\n```text\n'
      NO_COLOR=1 TERM=dumb ${pkgs.copyparty}/bin/copyparty --help 2>&1 || true
      printf '\n```\n'
    } > "$work/src/reference/copyparty-help.md"
    {
      printf '# CopyParty volume flags\n\nGenerated from the installed CopyParty package.\n\n```text\n'
      NO_COLOR=1 TERM=dumb ${pkgs.copyparty}/bin/copyparty --help-flags 2>&1 || true
      printf '\n```\n'
    } > "$work/src/reference/copyparty-flags.md"

    emit_source() {
      title="$1"
      source="$2"
      destination="$3"
      language="$4"
      {
        printf '# %s\n\nGenerated from the release source tree.\n\n```%s\n' "$title" "$language"
        cat "$source"
        printf '\n```\n'
      } > "$work/src/reference/$destination"
    }
    emit_source "Disko OS-disk example" ${../../../installation/disko-os-disk-example.nix} disko-os-disk-example.md nix
    emit_source "Disko fresh-pool example" ${../../../installation/disko-fresh-pool-example.nix} disko-fresh-pool-example.md nix
    emit_source "Pool-layout worksheet" ${../../../installation/pool-layout.md} pool-layout.md markdown
    emit_source "Authentik NAS user-settings blueprint" ${../../../authentik/blueprints/nas-user-settings.yaml} authentik-nas-user-settings-blueprint.md yaml

    {
      printf '# Cockpit NAS UI source\n\nGenerated from the exact React and PatternFly release source.\n'
      cockpit_source=${../../../cockpit/src}
      while IFS= read -r -d "" source; do
        relative="$(realpath --relative-to="$cockpit_source" "$source")"
        printf '\n## %s\n\n```text\n' "$relative"
        cat "$source"
        printf '\n```\n'
      done < <(find "$cockpit_source" -type f -print0 | sort -z)
    } > "$work/src/reference/cockpit-source.md"

    append_source() {
      title="$1"
      source="$2"
      destination="$3"
      language="$4"
      {
        printf '\n## %s\n\nSource: `%s`\n\n```%s\n' "$title" "$destination" "$language"
        cat "$source"
        printf '\n```\n'
      }
    }

    {
      printf '# NAS and AI Nix option source\n\n'
      printf 'Generated from the exact option modules in this release. Search this page for an option name, default, type, or description.\n'
      append_source "Core NAS options" ${../../../modules/nas/options/core.nix} modules/nas/options/core.nix nix
      append_source "Application options" ${../../../modules/nas/options/applications.nix} modules/nas/options/applications.nix nix
      append_source "Hardware options" ${../../../modules/nas/options/hardware.nix} modules/nas/options/hardware.nix nix
      append_source "Management options" ${../../../modules/nas/options/management.nix} modules/nas/options/management.nix nix
      append_source "Operations options" ${../../../modules/nas/options/operations.nix} modules/nas/options/operations.nix nix
      append_source "Power options" ${../../../modules/nas/options/power.nix} modules/nas/options/power.nix nix
      append_source "Storage options" ${../../../modules/nas/options/storage.nix} modules/nas/options/storage.nix nix
      append_source "Virtualization options" ${../../../modules/nas/options/virtualization.nix} modules/nas/options/virtualization.nix nix
      append_source "AI options" ${../../../modules/ai/options.nix} modules/ai/options.nix nix
    } > "$work/src/reference/nix-options-source.md"

    {
      printf '# Deployed custom configuration source\n\n'
      printf 'Generated from the exact release source. These pages are reference-only; edit the repository and rebuild rather than changing generated documentation.\n'
      append_source "Operator configuration template" ${../../../local.nix} local.nix nix
      append_source "Reverse proxy and authorization routes" ${../../../modules/nas/config/reverse-proxy.nix} modules/nas/config/reverse-proxy.nix nix
      append_source "Application service definitions" ${../../../modules/nas/config/application-services.nix} modules/nas/config/application-services.nix nix
      append_source "System and mutable seed configuration" ${../../../modules/nas/config/system.nix} modules/nas/config/system.nix nix
      append_source "Systemd service definitions" ${../../../modules/nas/config/systemd-services.nix} modules/nas/config/systemd-services.nix nix
      append_source "Identity and local accounts" ${../../../modules/nas/config/identities.nix} modules/nas/config/identities.nix nix
      append_source "Network and firewall" ${../../../modules/nas/config/network-firewall.nix} modules/nas/config/network-firewall.nix nix
      append_source "Observability and alerts" ${../../../modules/nas/config/observability.nix} modules/nas/config/observability.nix nix
      append_source "Schedules" ${../../../modules/nas/config/schedules.nix} modules/nas/config/schedules.nix nix
      append_source "Storage and monitoring" ${../../../modules/nas/config/storage-monitoring.nix} modules/nas/config/storage-monitoring.nix nix
      append_source "Virtualization" ${../../../modules/nas/config/virtualization.nix} modules/nas/config/virtualization.nix nix
      append_source "Secret activation tooling" ${../../../modules/nas/internal/secret-tools.nix} modules/nas/internal/secret-tools.nix nix
      append_source "Account and command tooling" ${../../../modules/nas/internal/account-tools.nix} modules/nas/internal/account-tools.nix nix
      append_source "Documentation and Cockpit packaging" ${../../../modules/nas/internal/documentation-tools.nix} modules/nas/internal/documentation-tools.nix nix
      append_source "Maintenance tooling" ${../../../modules/nas/internal/maintenance-tools.nix} modules/nas/internal/maintenance-tools.nix nix
      append_source "Power tooling" ${../../../modules/nas/internal/power-tools.nix} modules/nas/internal/power-tools.nix nix
      append_source "Storage tooling" ${../../../modules/nas/internal/zfs-tools.nix} modules/nas/internal/zfs-tools.nix nix
      append_source "Core internal context" ${../../../modules/nas/internal/base.nix} modules/nas/internal/base.nix nix
      append_source "Feature catalog and policy" ${../../../modules/nas/internal/feature-catalog.nix} modules/nas/internal/feature-catalog.nix nix
      append_source "Capability and group registry" ${../../../modules/nas/internal/capability-registry.nix} modules/nas/internal/capability-registry.nix nix
      append_source "Capability registry schema" ${../../../schemas/capability-registry.schema.json} schemas/capability-registry.schema.json json
      append_source "Caddy authorization helpers" ${../../../modules/nas/internal/caddy-helpers.nix} modules/nas/internal/caddy-helpers.nix nix
      append_source "Identity reconciler" ${../../../services/nas_identity_sync.py} services/nas_identity_sync.py python
      append_source "First-run setup orchestrator" ${../../../services/nas_setup.py} services/nas_setup.py python
      append_source "First-run setup example" ${../../../setup/first-run.example.json} setup/first-run.example.json json
      append_source "Syncthing device validator" ${../../../services/nas_syncthing_devices.py} services/nas_syncthing_devices.py python
      append_source "Feature controller" ${../../../services/nas_feature_control.py} services/nas_feature_control.py python
      append_source "Cockpit privileged API" ${../../../services/nas_cockpit_api.py} services/nas_cockpit_api.py python
      append_source "Caddy portal template" ${../../../web/portal/index.html} web/portal/index.html html
      append_source "AI runtime services" ${../../../modules/ai/services.nix} modules/ai/services.nix nix
      append_source "AI downloader" ${../../../modules/ai/downloader.nix} modules/ai/downloader.nix nix
      append_source "AI default configuration" ${../../../modules/ai/internal.nix} modules/ai/internal.nix nix
      append_source "Flake outputs and inputs" ${../../../flake.nix} flake.nix nix
      append_source "Renovate policy" ${../../../renovate.json} renovate.json json
      append_source "Continuous integration" ${../../../.github/workflows/ci.yml} .github/workflows/ci.yml yaml
    } > "$work/src/reference/configuration-source.md"

    mkdir -p "$out/share/cockpit/nas/docs"
    mdbook build "$work" --dest-dir "$out/share/cockpit/nas/docs"
  '';

  cockpitNasPlugin = pkgs.runCommand "cockpit-nas-management" {
    nativeBuildInputs = [ pkgs.nodejs ];
  } ''
    cd ${../../../cockpit}
    node build.js --check
    cockpit_dist=${../../../cockpit/dist}
    for asset in manifest.json index.html index.js index.css build-meta.json; do
      test -s "$cockpit_dist/$asset" || {
        printf 'Cockpit React/PatternFly bundle is missing %s. Restore the reviewed lockfile, run npm ci, then npm run build in cockpit/.\n' "$asset" >&2
        exit 1
      }
    done
    install -d "$out/share/cockpit/nas"
    cp -R "$cockpit_dist/." "$out/share/cockpit/nas/"
    cp -R ${nasDocumentation}/share/cockpit/nas/docs "$out/share/cockpit/nas/docs"
  '';
in
{
  inherit nasDocumentation cockpitNasPlugin;
}
