{ lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal) cockpitPort;
  desiredPath = "/var/lib/nas-control/services.yaml";
  markerPath = "/var/lib/nas-control/.managed-services-platform-routes-seed-v2";
  schemaPath = "/etc/nas-control/managed-services-v3.schema.json";
  platformPath = "/etc/nas-control/platform-capabilities.json";
  v2Source = ../../../services;
  v2Python = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    defusedxml
    jsonschema
    ruamel-yaml
  ]);
  yamlFormat = pkgs.formats.yaml { };
  seedFile = yamlFormat.generate "managed-services-platform-routes-seed-v2.yaml" {
    schemaVersion = 3;
    services.cockpit = {
      name = "Cockpit system administration";
      managed = false;
      workload = {
        kind = "daemon";
        activation = "persistent";
      };
      runtime = {
        type = "systemd";
        unit = "cockpit.socket";
      };
      authorization.capabilities = [
        { id = "admin"; title = "Administer the NAS with Cockpit"; }
      ];
      routes.console = {
        exposure = {
          type = "path";
          paths = [ "/console" ];
        };
        target = {
          type = "http";
          host = "127.0.0.1";
          port = cockpitPort;
        };
        auth = {
          mode = "identity";
          capability = "admin";
        };
        proxy.requestHeaders = {
          "X-Forwarded-Proto" = "https";
          "X-Forwarded-Prefix" = "/console";
        };
        portal = {
          visible = true;
          title = "System Console";
          category = "Administration";
          icon = "terminal";
          order = 5;
        };
      };
    };
  };
in
{
  config.systemd.services.nas-managed-services-seed = {
    environment.PYTHONPATH = "${v2Source}";
    postStart = lib.mkAfter ''
      ${v2Python}/bin/python ${v2Source}/nas_v2_bootstrap.py \
        --desired ${lib.escapeShellArg desiredPath} \
        --seed ${lib.escapeShellArg seedFile} \
        --marker ${lib.escapeShellArg markerPath} \
        --schema ${lib.escapeShellArg schemaPath} \
        --platform ${lib.escapeShellArg platformPath}
    '';
    serviceConfig.ReadWritePaths = lib.mkAfter [ "/var/lib/nas-control" ];
  };
}
