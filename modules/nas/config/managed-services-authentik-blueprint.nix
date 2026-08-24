{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  v2Source = ../../../services;
  v2Python = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    jsonschema
    ruamel-yaml
  ]);
  effectivePath = "/run/nas-control/effective.json";
  blueprintDir = "${nasInternal.authentikDataDir}/blueprints";
  blueprintName = "nas-managed-services-v2.yaml";
  blueprintPath = "${blueprintDir}/${blueprintName}";
  objectManifest = "/var/lib/nas-control/authentik-v2-objects.json";
  nextManifest = "/run/nas-control/authentik-v2-objects.next.json";
  staticBlueprint = "${nasInternal.nasAuthentikBlueprints}/share/authentik/blueprints/nas-user-settings.yaml";
  authentikEnvironment = nasInternal.authentikRuntimeEnvironmentFile;
  reconcileScript = pkgs.writeShellScript "nas-v2-authentik-blueprint-apply" ''
    set -euo pipefail
    export PYTHONPATH=${lib.escapeShellArg (toString v2Source)}

    ${v2Python}/bin/python ${v2Source}/nas_v2_authentik_blueprint.py generate \
      --effective ${lib.escapeShellArg effectivePath} \
      --blueprint ${lib.escapeShellArg blueprintPath} \
      --manifest ${lib.escapeShellArg objectManifest} \
      --next-manifest ${lib.escapeShellArg nextManifest} \
      --public-host ${lib.escapeShellArg cfg.identity.publicHost}

    # apply_blueprint resolves paths beneath AUTHENTIK_BLUEPRINTS_DIR, validates
    # the complete blueprint first, and applies it in Authentik's atomic DB
    # transaction. Preserve the service EnvironmentFile while dropping to the
    # native Authentik account for database/socket access.
    ${pkgs.util-linux}/bin/runuser \
      --user authentik \
      --preserve-environment \
      -- ${pkgs.coreutils}/bin/env \
        HOME=${lib.escapeShellArg nasInternal.authentikDataDir} \
        AUTHENTIK_BLUEPRINTS_DIR=${lib.escapeShellArg blueprintDir} \
        ${pkgs.authentik}/bin/ak apply_blueprint ${lib.escapeShellArg blueprintName}

    ${v2Python}/bin/python ${v2Source}/nas_v2_authentik_blueprint.py commit \
      --manifest ${lib.escapeShellArg objectManifest} \
      --next-manifest ${lib.escapeShellArg nextManifest}
  '';
in
{
  config = {
    # Keep both repository-owned and generated blueprints in one writable
    # directory. The static file stays an immutable symlink; V2 owns only its
    # generated file and generated-object cache.
    systemd.tmpfiles.rules = [
      "d ${blueprintDir} 0750 authentik authentik -"
      "L+ ${blueprintDir}/nas-user-settings.yaml - - - - ${staticBlueprint}"
    ];

    # Authentik's worker continues to watch this directory natively. The V2
    # reconcile unit also invokes `ak apply_blueprint` synchronously, so a file
    # watcher is convenience/recovery rather than the transaction boundary.
    systemd.services.authentik.environment.AUTHENTIK_BLUEPRINTS_DIR = blueprintDir;
    systemd.services.authentik-worker.environment.AUTHENTIK_BLUEPRINTS_DIR = blueprintDir;
    systemd.services.authentik-migrate.environment.AUTHENTIK_BLUEPRINTS_DIR = blueprintDir;

    # Replace the REST CRUD reconciler. A normal lower-priority override is
    # sufficient here; unlike mkForce it does not bypass the repository's
    # audited module merge policy. No API token, HTTP access, pagination,
    # provider CRUD, outpost mutation, or membership mutation is required.
    systemd.services.nas-managed-services-authentik-reconcile = {
      description = lib.mkOverride 900 "Apply Managed Services V2 Authentik blueprint";
      unitConfig.ConditionPathExists = lib.mkOverride 900 [ effectivePath authentikEnvironment ];
      environment = {
        PYTHONPATH = toString v2Source;
        AUTHENTIK_BLUEPRINTS_DIR = blueprintDir;
      };
      serviceConfig = {
        ExecStart = lib.mkOverride 900 reconcileScript;
        EnvironmentFile = [ authentikEnvironment ];
        ReadWritePaths = [ blueprintDir "/var/lib/nas-control" "/run/nas-control" ];
        RestrictAddressFamilies = lib.mkOverride 900 [ "AF_UNIX" ];
      };
    };
  };
}
