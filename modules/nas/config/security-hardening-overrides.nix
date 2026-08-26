{ lib, ... }:

{
  # systemd-services.nix historically started a standalone Authentik proxy
  # outpost after identity bootstrap. The hardened stack uses Authentik's
  # embedded outpost instead, so force the inherited post-start hook empty.
  # Keeping the override explicit also prevents a stale module definition from
  # resurrecting the retired privileged daemon through option merging.
  systemd.services.nas-identity-bootstrap = {
    description = lib.mkForce "Reconcile the Authentik portal provider for the embedded outpost";
    serviceConfig.ExecStartPost = lib.mkForce [ ];
  };
}
