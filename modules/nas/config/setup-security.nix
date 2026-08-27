{ config, lib, pkgs, ... }:

{
  # First-start status is consumed through the authenticated setup API. There
  # is no reason for arbitrary local users to traverse the state directory.
  systemd.services.nas-first-start.serviceConfig.StateDirectoryMode =
    lib.mkOverride 40 "0700";

  # The locked/nologin bootstrap principal executes the finite first-run
  # transaction before the user-selected administrator exists. The permanent
  # KDBX is deliberately root:nas-administrators 0660 during that handoff, so
  # grant only this file-access group after the hardening override has reduced
  # the bootstrap account to wheel. The account is deleted at setup commit.
  systemd.services.nas-bootstrap-administrator = lib.mkIf config.nas.firstStart.enable {
    serviceConfig.ExecStartPost = [
      "${pkgs.shadow}/bin/usermod --append --groups nas-administrators nas-bootstrap"
    ];
  };
}
