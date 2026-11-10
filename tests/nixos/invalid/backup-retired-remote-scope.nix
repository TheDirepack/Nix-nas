{ lib, ... }:

{
  nas.backup = {
    enable = lib.mkOverride 10 true; # module-consumer.nix forces it off
    passwordFile = "/run/secrets/restic-password";
    repositoryFile = "/run/secrets/restic-repository";
    remote.scope = "all";
  };
}
