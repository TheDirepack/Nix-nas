{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  desiredPath = "/var/lib/nas-control/services.yaml";
  markerPath = "/var/lib/nas-control/.managed-services-direct-listeners-seed-v2";
  schemaPath = "/etc/nas-control/managed-services-v3.schema.json";
  platformPath = "/etc/nas-control/platform-capabilities.json";
  v2Source = ../../../services;
  v2Python = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    defusedxml
    jsonschema
    ruamel-yaml
  ]);
  yamlFormat = pkgs.formats.yaml { };

  tftpListeners = {
    request = {
      protocol = "udp";
      exposure.port = cfg.tftp.port;
      targetPort = cfg.tftp.internalPort;
      firewall = true;
    };
    responses = {
      protocol = "udp";
      exposure = {
        start = cfg.tftp.responsePortStart;
        end = cfg.tftp.responsePortEnd;
      };
      firewall = true;
    };
  };

  seedFile = yamlFormat.generate "managed-services-direct-listeners-seed-v2.yaml" {
    schemaVersion = 3;
    services = lib.optionalAttrs cfg.tftp.enable {
      tftp = {
        name = "CopyParty TFTP endpoint";
        description = "LAN-scoped TFTP ingress backed by the native CopyParty service.";
        managed = false;
        workload = {
          kind = "daemon";
          activation = "persistent";
        };
        runtime = {
          type = "systemd";
          unit = "copyparty.service";
        };
        listeners = tftpListeners;
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
