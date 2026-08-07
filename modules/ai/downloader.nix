{ config, lib, pkgs, aiInternal, ... }:

let
  inherit (aiInternal)
    aiRoot
    aiSecretDir
    cfg
    downloaderImage
    hfRoot
  ;
in
{
  config = lib.mkIf cfg.enable {
    virtualisation.oci-containers.containers.hfdownloader = lib.mkIf cfg.modelDownloader.enable {
      image = downloaderImage;
      pull = "missing";
      ports = [ "127.0.0.1:${toString cfg.modelDownloader.port}:8080" ];
      cmd = [ "serve" "--port" "8080" ];
      environment = {
        HF_HOME = "/home/hfdownloader/.cache/huggingface";
        HOME = "/home/hfdownloader";
      };
      environmentFiles = [ "${aiSecretDir}/hfdownloader.env" ];
      volumes = [
        "${hfRoot}:/home/hfdownloader/.cache/huggingface:rw"
        "${aiRoot}/downloader-config:/home/hfdownloader/.config:rw"
      ];
      podman.user = "hfdownloader";
      extraOptions = [
        "--userns=keep-id:uid=1000,gid=1000"
        "--group-add=keep-groups"
        "--cap-drop=ALL"
        "--security-opt=no-new-privileges"
        "--pids-limit=512"
        "--memory=2g"
      ];
      autoRemoveOnStop = true;
    };
  };
}
