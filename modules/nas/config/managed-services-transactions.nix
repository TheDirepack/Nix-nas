{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  zfsControlRoot = "${cfg.zfsRoot}/nas-control";
  desiredPath = "/var/lib/nas-control/services.yaml";
  historyRepoPath = "${zfsControlRoot}/config-history.git";
  systemdProjectionPath = "/run/nas-control/systemd";
  systemdManifestPath = "${systemdProjectionPath}/manifest.json";
  systemdStatePath = "/run/nas-control/systemd-reconciled.json";
  firewalldProjectionPath = "/run/nas-control/firewalld";
  firewalldManifestPath = "${firewalldProjectionPath}/manifest.json";
  firewalldSystemConfig = "/var/lib/nas-firewall/firewalld";
  quadletRuntimePath = "/run/containers/systemd";
  v2Source = ../../../services;
  v2Python = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    defusedxml
    jsonschema
    ruamel-yaml
  ]);
  firewalldEnabled = cfg.networking.enable && cfg.networking.firewall.enable;
  firewalldPackage = config.services.firewalld.package;
  historyArgs = [
    "${v2Source}/nas_v2_history.py"
    "--authority"
    desiredPath
    "--repository"
    historyRepoPath
    "--git-bin"
    "${pkgs.git}/bin/git"
  ];
  statelessFirewalldArgs = [
    "${v2Source}/nas_v2_firewalld_reconcile.py"
    "--manifest"
    firewalldManifestPath
    "--projection-root"
    firewalldProjectionPath
    "--system-config"
    firewalldSystemConfig
    "--firewall-cmd"
    "${firewalldPackage}/bin/firewall-cmd"
  ];
  systemdReconcileArgs = [
    "${v2Source}/nas_v2_systemd_reconcile.py"
    "--manifest"
    systemdManifestPath
    "--projection-root"
    systemdProjectionPath
    "--systemd-runtime-dir"
    "/run/systemd/system"
    "--quadlet-runtime-dir"
    quadletRuntimePath
    "--state"
    systemdStatePath
    "--systemctl"
    "${pkgs.systemd}/bin/systemctl"
  ];
  rollbackToApplied = pkgs.writeShellScript "nas-v2-rollback-to-applied" ''
    set -euo pipefail
    export PYTHONPATH=${lib.escapeShellArg (toString v2Source)}

    if ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} restore-applied; then
      # services.yaml changed under the active path unit. Queue a fresh finite
      # reconciliation from the known-good Git revision. If the failed apply is
      # still running, restart also terminates it instead of waiting forever.
      ${pkgs.systemd}/bin/systemctl restart nas-managed-services-reconcile.service
      exit 0
    fi

    # First boot has no refs/nas/applied yet. The immutable Nix firewall
    # baseline is the only safe fallback: remove the V2 namespace and reload it.
    ${lib.optionalString firewalldEnabled ''
    ${pkgs.findutils}/bin/find \
      ${lib.escapeShellArg "${firewalldSystemConfig}/zones"} \
      ${lib.escapeShellArg "${firewalldSystemConfig}/policies"} \
      -maxdepth 1 -type f -name 'nv2*.xml' -delete
    ${firewalldPackage}/bin/firewall-cmd --check-config
    ${firewalldPackage}/bin/firewall-cmd --reload
    ''}
    exit 1
  '';
  guardArmArgs = [
    "${v2Source}/nas_guarded_apply.py"
    "--unit"
    "nas-v2-apply-rollback"
    "--systemctl"
    "${pkgs.systemd}/bin/systemctl"
    "arm"
    "--timeout"
    "60"
    "--systemd-run"
    "${pkgs.systemd}/bin/systemd-run"
    "--"
    rollbackToApplied
  ];
  guardCancelArgs = [
    "${v2Source}/nas_guarded_apply.py"
    "--unit"
    "nas-v2-apply-rollback"
    "--systemctl"
    "${pkgs.systemd}/bin/systemctl"
    "cancel"
  ];
in
{
  config = {
    # Record the exact desired-state text before compilation. Git tracks only
    # services.yaml; generated projections and runtime state stay out of history.
    systemd.services.nas-managed-services-reconcile.preStart = lib.mkBefore ''
      ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} record
    '';

    # Replace the old firewall-specific deadman/ack sequence with one generic
    # apply guard around all core runtime mutation. Native subsystem rollback can
    # still happen inside an adapter; this guard covers process crashes and
    # cross-subsystem failures by restoring refs/nas/applied.
    systemd.services.nas-managed-services-reconcile.postStart = lib.mkForce ''
      set -euo pipefail
      ${v2Python}/bin/python ${lib.escapeShellArgs guardArmArgs}

      rollback_desired() {
        ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} restore-applied >/dev/null 2>&1 || true
      }
      trap rollback_desired ERR

      ${lib.optionalString firewalldEnabled ''
      ${v2Python}/bin/python ${lib.escapeShellArgs statelessFirewalldArgs}
      ''}
      ${v2Python}/bin/python ${lib.escapeShellArgs systemdReconcileArgs}

      # The core runtime projection has now been applied and verified. Keep this
      # as a dedicated ref instead of inferring success from Git HEAD.
      ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} mark-applied
      ${v2Python}/bin/python ${lib.escapeShellArgs guardCancelArgs}
      trap - ERR
    '';

    # The original per-firewall acknowledgement protocol is superseded by the
    # generic transaction guard above. Keep the old definitions inert until the
    # remaining dead code is deleted from managed-services.nix/nas_v2_network.py.
    systemd.services.nas-v2-firewall-rollback.enable = lib.mkForce false;
    systemd.timers.nas-v2-firewall-rollback.enable = lib.mkForce false;
  };
}
