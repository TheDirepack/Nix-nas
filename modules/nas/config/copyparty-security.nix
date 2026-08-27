{ lib, ... }:

{
  # Caddy only needs to connect to CopyParty's private HTTP socket. Do not make
  # the reverse proxy a member of CopyParty's data-owning group, because the
  # share tree is intentionally group-writable under CopyParty's 0007 umask.
  users.groups.nas-copyparty-proxy = { };
  users.users.caddy.extraGroups = lib.mkAfter [ "nas-copyparty-proxy" ];
  users.users.copyparty.extraGroups = lib.mkAfter [ "nas-copyparty-proxy" ];

  services.copyparty.settings.i =
    lib.mkForce "unix:660:nas-copyparty-proxy:/run/copyparty/http.sock";
}
