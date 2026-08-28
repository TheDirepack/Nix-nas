{ ... }:

{
  # First-start jobs are transient units named nas-first-start-<job>.service.
  # systemd applies dash-prefix drop-ins after the transient unit fragment, so
  # this keeps the long-lived setup API tightly sandboxed while granting only
  # the short-lived provisioning worker the host access its reviewed setup
  # transaction requires.
  #
  # The worker creates the selected local administrator, initializes runtime
  # secrets, and may create ZFS on an explicitly confirmed block device. The
  # transient launcher keeps NoNewPrivileges=yes and PrivateTmp=yes; this
  # drop-in only restores /dev, /home, /etc, /var, and /run access needed by
  # those provisioning operations while /usr and /boot remain read-only.
  environment.etc."systemd/system/nas-first-start-.service.d/20-setup-access.conf".text = ''
    [Service]
    PrivateDevices=no
    ProtectHome=no
    ProtectSystem=yes
    ReadWritePaths=
  '';
}
