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

    # If this is the immediate OnFailure path, disarm the timer for the failed
    # desired revision before creating the rollback commit. If the timer itself
    # invoked this script, stopping its timer is harmless.
    failed_head="$(${pkgs.git}/bin/git --git-dir=${lib.escapeShellArg historyRepoPath} rev-parse --verify HEAD 2>/dev/null || true)"
    if [ -n "$failed_head" ]; then
      suffix="$(printf '%s' "$failed_head" | ${pkgs.coreutils}/bin/cut -c1-12)"
      ${pkgs.systemd}/bin/systemctl stop "nas-v2-apply-rollback-$suffix.timer" >/dev/null 2>&1 || true
    fi

    if ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} restore-applied; then
      # Reconcile from the known-good Git revision. restore-applied records a
      # new rollback commit, so the next guard gets a different transient unit
      # name and cannot collide with the failed attempt's rollback service.
      ${pkgs.systemd}/bin/systemctl restart nas-managed-services-reconcile.service
      exit 0
    fi

    # First boot has no refs/nas/applied yet. The immutable Nix firewall
    # baseline is the only safe runtime fallback. There is no older mutable
    # desired state to restore in this case.
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
  guardUnitShell = ''
    desired_head="$(${pkgs.git}/bin/git --git-dir=${lib.escapeShellArg historyRepoPath} rev-parse --verify HEAD)"
    guard_suffix="$(printf '%s' "$desired_head" | ${pkgs.coreutils}/bin/cut -c1-12)"
    guard_unit="nas-v2-apply-rollback-$guard_suffix"
  '';
in
{
  config = {
    # Commit and arm rollback before compilation. This covers schema/compiler
    # failures as well as failures in runtime projection activation.
    systemd.services.nas-managed-services-reconcile.preStart = lib.mkBefore ''
      ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} record
      ${guardUnitShell}
      ${v2Python}/bin/python ${v2Source}/nas_guarded_apply.py \
        --unit "$guard_unit" \
        --systemctl ${lib.escapeShellArg "${pkgs.systemd}/bin/systemctl"} \
        arm \
        --timeout 60 \
        --systemd-run ${lib.escapeShellArg "${pkgs.systemd}/bin/systemd-run"} \
        -- ${rollbackToApplied}
    '';

    # A normal failure gets the same rollback immediately; the transient timer
    # remains the crash/deadlock fallback when systemd never reaches OnFailure.
    systemd.services.nas-managed-services-reconcile.onFailure = lib.mkAfter [
      "nas-v2-apply-failed.service"
    ];
    systemd.services.nas-v2-apply-failed = {
      description = "Restore the last applied Managed Services V2 desired state";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = rollbackToApplied;
      };
    };

    # Replace the old firewall-specific deadman/ack sequence with one generic
    # apply guard around the complete compiler + core runtime transaction.
    systemd.services.nas-managed-services-reconcile.postStart = lib.mkForce ''
      set -euo pipefail

      ${lib.optionalString firewalldEnabled ''
      ${v2Python}/bin/python ${lib.escapeShellArgs statelessFirewalldArgs}
      ''}
      ${v2Python}/bin/python ${lib.escapeShellArgs systemdReconcileArgs}

      # The core runtime projection has now been applied and verified. Keep this
      # as a dedicated ref instead of inferring success from Git HEAD.
      ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} mark-applied
      ${guardUnitShell}
      ${v2Python}/bin/python ${v2Source}/nas_guarded_apply.py \
        --unit "$guard_unit" \
        --systemctl ${lib.escapeShellArg "${pkgs.systemd}/bin/systemctl"} \
        cancel
    '';

    # The original per-firewall acknowledgement protocol is superseded by the
    # generic transaction guard above. Keep the old definitions inert until the
    # remaining dead code is deleted from managed-services.nix/nas_v2_network.py.
    systemd.services.nas-v2-firewall-rollback.enable = lib.mkForce false;
    systemd.timers.nas-v2-firewall-rollback.enable = lib.mkForce false;
  };
}
