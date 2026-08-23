args:
let
  inherit (args)
    nasIdentitySync
    nasPythonApplication
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
    emit_help nas-managed-services-control ${nasPythonApplication}/bin/nas-managed-services-control
    emit_help nas-managed-services ${nasPythonApplication}/bin/nas-managed-services
    emit_help nas-state ${nasState}/bin/nas-state
    emit_help nas-secrets ${nasSecrets}/bin/nas-secrets
    emit_help nas-update ${nasUpdate}/bin/nas-update

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

    mkdir -p "$out/share/cockpit/nas/docs"
    mdbook build "$work" --dest-dir "$out/share/cockpit/nas/docs"
  '';

  cockpitNasPlugin =
    let
      plugin = pkgs.runCommand "cockpit-nas-management" {
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
    plugin // {
      passthru.cockpitPath = [ plugin ];
    };
in
{
  inherit nasDocumentation cockpitNasPlugin;
}
