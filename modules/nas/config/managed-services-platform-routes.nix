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
in
{
  # Platform cockpit route is now part of the single aggregated seed in
  # managed-services-seed-v2.nix. Retaining this module as a no-op keeps
  # historical imports stable while ensuring only one bootstrap runs.
}
