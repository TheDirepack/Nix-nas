{ lib, ... }:

{
  nas.backup = {
    enable = lib.mkOverride 10 true; # module-consumer.nix forces it off
    passwordFile = "/run/secrets/restic-password";
    localRepository = "/mnt/usb/restic";
  };
}
