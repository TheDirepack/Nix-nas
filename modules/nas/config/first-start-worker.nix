{ ... }:

{
  # First-start jobs are transient units named nas-first-start-<job>.service.
  # systemd applies dash-prefix drop-ins after the transient unit fragment, so
  # this keeps the long-lived setup API tightly sandboxed while granting only
  # the short-lived provisioning worker the host access its reviewed setup
  # transaction requires.
  #
  # Define the prefix override through NixOS' systemd unit machinery instead of
  # environment.etc. /etc/systemd/system is assembled from the generated
  # system-units derivation, so trying to create a nested drop-in directory
  # there from etc.drv collides with the store-backed systemd tree.
  #
  # The worker creates the selected local administrator, initializes runtime
  # secrets, and may create ZFS on an explicitly confirmed block device. Keep
  # NoNewPrivileges and PrivateTmp from the transient launcher while restoring
  # the host access required by those provisioning operations. ProtectSystem
  # remains enabled, keeping /usr and /boot read-only while /etc and /var are
  # writable for the first-start transaction.
  systemd.services."nas-first-start-" = {
    overrideStrategy = "asDropin";
    serviceConfig = {
      PrivateDevices = false;
      ProtectHome = false;
      ProtectSystem = "yes";
      ReadWritePaths = [
        "/var/lib/nas-secrets"
        "/var/lib/nas-setup"
        "/var/lib/nas-control"
        "/var/lib/postgresql"
        "/run/nas-secrets"
      ];
    };
  };
}
