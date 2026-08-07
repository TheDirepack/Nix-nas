args:
let
  inherit (args)
    cfg
    tftpMountRoot
  ;
  mkTftpVolume = {
    path = tftpMountRoot;
    # TFTP access is granted through CopyParty's anonymous VFS principal.
    access = if cfg.tftp.writable then { rw = "*"; } else { r = "*"; };
    flags = {
      noidx = true;
      nohtml = true;
      "no-readme" = true;
      "no-logues" = true;
      chmod_f = "660";
      chmod_d = "770";
    };
  };

in
{
  inherit mkTftpVolume;
};
