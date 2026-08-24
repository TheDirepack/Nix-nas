{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  zfsControlRoot = "${cfg.zfsRoot}/nas-control";
  desiredPath = "/var/lib/nas-control/services.yaml";
  effectivePath = "/run/nas-control/effective.json";
  historyRepoPath = "${zfsControlRoot}/config-history.git";
  planPath = "/run/nas-control/plan.json";
  reconcilePendingPath = "/run/nas-control/reconcile.pending";
  systemdProjectionPath = "/run/nas-control/systemd";
  systemdManifestPath = "${systemdProjectionPath}/manifest.json";
  systemdStatePath = "/run/nas-control/systemd-reconciled.json";
  firewalldProjectionPath = "/run/nas-control/firewalld";
  firewalldManifestPath = "${firewalldProjectionPath}/manifest.json";
  quadletRuntimePath = "/run/containers/systemd";
  v2Source = ../../../services;
  v2Python = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    defusedxml
    jsonschema
    ruamel-yaml
  ]);
  networkingEnabled = cfg.networking.enable;
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
  nmstateArgs = [
    "${v2Source}/nas_v2_nmstate.py"
    "--effective"
    effectivePath
    "--nmstatectl"
    "${pkgs.nmstate}/bin/nmstatectl"
  ] ++ lib.optionals (cfg.networking.applicationVlanParent != null) [
    "--vlan-parent"
    cfg.networking.applicationVlanParent
  ];
  statelessFirewalldArgs = [
    "${v2Source}/nas_v2_firewalld_reconcile.py"
    "--manifest"
    firewalldManifestPath
    "--projection-root"
    firewalldProjectionPath
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

    # If the timer fired because reconciliation wedged, stop the owning unit
    # first so it cannot keep mutating runtime projections during rollback.
    ${pkgs.systemd}/bin/systemctl stop nas-managed-services-reconcile.service >/dev/null 2>&1 || true
    ${pkgs.systemd}/bin/systemctl stop 'nas-v2-apply-rollback-*.timer' >/dev/null 2>&1 || true

    # Prefer the exact compiled revision. If compilation failed before plan.json
    # was materialized, HEAD is the revision recorded under the authority lock.
    failed_head=""
    if [ -r ${lib.escapeShellArg planPath} ]; then
      failed_head="$(${pkgs.jq}/bin/jq -er '.desiredRevision | select(type == "string" and length > 0)' ${lib.escapeShellArg planPath} 2>/dev/null || true)"
    fi
    if [ -z "$failed_head" ]; then
      failed_head="$(${pkgs.git}/bin/git \
        --git-dir=${lib.escapeShellArg historyRepoPath} \
        --work-tree=${lib.escapeShellArg (builtins.dirOf desiredPath)} \
        rev-parse --verify HEAD 2>/dev/null || true)"
    fi

    restore_args=(${lib.escapeShellArgs historyArgs} restore-applied)
    if [ -n "$failed_head" ]; then
      restore_args+=(--failed-commit "$failed_head")
    fi

    if ${v2Python}/bin/python "''${restore_args[@]}"; then
      # restore-applied refuses to overwrite a newer desired edit. In either
      # case, restart once: restored state needs reprojection, while a newer
      # edit needs its own finite transaction. nmstate/firewalld/systemd are all
      # regenerated from that restored/current authority on the next run.
      ${pkgs.systemd}/bin/systemctl restart nas-managed-services-reconcile.service
      exit 0
    fi

    # First boot has no refs/nas/applied yet. There is no older mutable desired
    # state to restore. Drop only the V2-owned native firewalld namespace and
    # leave the immutable Nix management baseline intact.
    ${lib.optionalString firewalldEnabled ''
    for policy in $(${firewalldPackage}/bin/firewall-cmd --permanent --get-policies); do
      if [[ "$policy" =~ ^nv2[zhwlrima][0-9a-f]{12}$ ]]; then
        ${firewalldPackage}/bin/firewall-cmd --permanent --delete-policy="$policy"
      fi
    done
    for zone in $(${firewalldPackage}/bin/firewall-cmd --permanent --get-zones); do
      if [[ "$zone" =~ ^nv2[zhwlrima][0-9a-f]{12}$ ]]; then
        ${firewalldPackage}/bin/firewall-cmd --permanent --delete-zone="$zone"
      fi
    done
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

    # Convert edge-triggered services.yaml notifications into a level-triggered
    # pending marker. systemd.path rechecks PathExists when the oneshot exits,
    # so an edit that arrives while reconciliation is active cannot be lost.
    systemd.services.nas-managed-services-dirty = {
      description = "Queue Managed Services V2 desired-state reconciliation";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.coreutils}/bin/touch ${reconcilePendingPath}";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/run/nas-control" ];
      };
    };
    systemd.paths.nas-managed-services-dirty = {
      description = "Notice Managed Services V2 desired-state changes";
      wantedBy = [ "multi-user.target" ];
      pathConfig = {
        PathChanged = desiredPath;
        Unit = "nas-managed-services-dirty.service";
      };
    };
    systemd.paths.nas-managed-services-reconcile.pathConfig = lib.mkForce {
      PathExists = reconcilePendingPath;
      Unit = "nas-managed-services-reconcile.service";
    };

    # Arm rollback before compilation. Remove the previous plan first so a
    # compile failure cannot accidentally identify an older invocation as the
    # failed revision.
    systemd.services.nas-managed-services-reconcile.preStart = lib.mkBefore ''
      ${pkgs.coreutils}/bin/rm -f ${lib.escapeShellArg planPath}
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

    # Native subsystem projections participate in one guarded finite apply.
    # nmstate owns host VLAN/VRF state, firewalld owns its permanent policy
    # objects, and systemd/Quadlet own process/container activation.
    systemd.services.nas-managed-services-reconcile.postStart = lib.mkForce ''
      set -euo pipefail

      # Pin success to the revision that was compiled, not whatever Git HEAD
      # might become after the compiler releases the authority lock.
      desired_head="$(${pkgs.jq}/bin/jq -er '.desiredRevision | select(type == "string" and length > 0)' ${lib.escapeShellArg planPath})"

      ${lib.optionalString networkingEnabled ''
      ${v2Python}/bin/python ${lib.escapeShellArgs nmstateArgs}
      ''}
      ${lib.optionalString firewalldEnabled ''
      ${v2Python}/bin/python ${lib.escapeShellArgs statelessFirewalldArgs}
      ''}
      ${v2Python}/bin/python ${lib.escapeShellArgs systemdReconcileArgs}

      ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} mark-applied --commit "$desired_head"

      # Clear the level-triggered marker only while the authority lock proves
      # the worktree still equals this exact compiled commit. A mid-apply edit
      # leaves the marker present and queues exactly one follow-up run.
      ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} ack-pending \
        --commit "$desired_head" \
        --pending ${lib.escapeShellArg reconcilePendingPath}

      ${guardUnitShell}
      ${v2Python}/bin/python ${v2Source}/nas_guarded_apply.py \
        --unit "$guard_unit" \
        --systemctl ${lib.escapeShellArg "${pkgs.systemd}/bin/systemctl"} \
        cancel
    '';

    # The original per-firewall acknowledgement protocol is superseded by the
    # generic transaction guard above.
    systemd.services.nas-v2-firewall-rollback.enable = lib.mkForce false;
    systemd.timers.nas-v2-firewall-rollback.enable = lib.mkForce false;
  };
}
