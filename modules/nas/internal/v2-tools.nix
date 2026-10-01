{ pkgs, ... }:

let
  v2Source = ../../../services;
  v2PythonCore = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    jsonschema
    ruamel-yaml
  ]);
  v2PythonXml = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    defusedxml
    jsonschema
    ruamel-yaml
  ]);
in
{
  inherit v2Source v2PythonCore v2PythonXml;
}
