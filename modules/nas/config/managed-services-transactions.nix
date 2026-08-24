{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  zfsControlRoot = "${cfg.zfsRoot}/nas-control";
  desiredPath = "/var/lib/nas-control/services.yaml";
  historyRepoPath = "${zfsControlRoot}/config-history.git";
  planPath = "/run/nas-control/plan.json";
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

    # The immediate OnFailure path and the timer fallback share the same
    # rollback action. Cancel any still-armed V2 timer before restoring state;
    # systemctl performs the unit-name glob expansion itself.
    ${pkgs.systemd}/bin/systemctl stop 'nas-v2-apply-rollback-*.timer' >/dev/null 2>&1 || true

    if ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} restore-applied; then
      # Reconcile from the known-good Git revision. restore-applied records a
      # new rollback commit, preserving the failed attempt in Git history.
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
    guard_suffix="$(printf '%s' "$INVOCATION_ID" | ${pkgs.coreutils}/bin/tr -d '-' | ${pkgs.coreutils}/bin/cut -c1-12)"
    test -n "$guard_suffix"
    guard_unit="nas-v2-apply-rollback-$guard_suffix"
  '';
in
{
  config = {
    # The compiler records the exact desired revision while holding the same
    # authority lock used to parse services.yaml. These environment variables
    # opt the production entry point into that history transaction.
    systemd.services.nas-managed-services-reconcile.environment.NAS_V2_HISTORY_REPOSITORY = historyRepoPath;
    systemd.services.nas-managed-services-reconcile.environment.NAS_V2_GIT_BIN = "${pkgs.git}/bin/git";

    # Arm rollback before compilation. A compile failure therefore follows the
    # same OnFailure path as a runtime activation failure, while the transient
    # timer remains the crash/deadlock fallback.
    systemd.services.nas-managed-services-reconcile.preStart = lib.mkBefore ''
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

      # Pin success to the revision that was compiled, not whatever Git HEAD
      # might become after the compiler releases the authority lock.
      desired_head="$(${pkgs.jq}/bin/jq -er '.desiredRevision | select(type == "string" and length > 0)' ${lib.escapeShellArg planPath})"

      ${lib.optionalString firewalldEnabled ''
      ${v2Python}/bin/python ${lib.escapeShellArgs statelessFirewalldArgs}
      ''}
      ${v2Python}/bin/python ${lib.escapeShellArgs systemdReconcileArgs}

      ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} mark-applied --commit "$desired_head"
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
