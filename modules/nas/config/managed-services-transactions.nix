{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  zfsControlRoot = "${cfg.zfsRoot}/nas-control";
  desiredPath = "/var/lib/nas-control/services.yaml";
  effectivePath = "/run/nas-control/effective.json";
  planPath = "/run/nas-control/plan.json";
  reconcilePendingPath = "/run/nas-control/reconcile.pending";
  caddyActivePath = "/run/nas-control/caddy-active.conf";
  historyRepoPath = "${zfsControlRoot}/config-history.git";
  systemdProjectionPath = "/run/nas-control/systemd";
  systemdManifestPath = "${systemdProjectionPath}/manifest.json";
  systemdStatePath = "/run/nas-control/systemd-reconciled.json";
  budgetFile = "/run/nas-control/apply-budget.json";
  guardStateDir = "/run/nas-control/rollback-guard";
  guardCurrentFile = "${guardStateDir}/current-guard-unit";
  firewalldProjectionPath = "/run/nas-control/firewalld";
  firewalldManifestPath = "${firewalldProjectionPath}/manifest.json";
  quadletRuntimePath = "/run/containers/systemd";
  v2Source = nasInternal.v2Source;
  v2Python = nasInternal.v2PythonXml;
  networkingEnabled = cfg.networking.enable;
  firewalldEnabled = cfg.networking.enable && cfg.networking.firewall.enable;
  firewalldPackage = config.services.firewalld.package;
  caddyPackage = config.services.caddy.package;
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
      # edit needs its own finite transaction.
      ${pkgs.systemd}/bin/systemctl restart nas-managed-services-reconcile.service
      exit 0
    fi

    # A missing applied revision is an unsafe history state, not a reason to
    # guess at native cleanup. Bootstrap creation above makes this unreachable
    # for a valid first transaction; leave all state untouched and fail closed.
    exit 1
  '';
  clearGuardCurrent = pkgs.writeShellScript "nas-v2-clear-current-guard" ''
    set -euo pipefail
    guard_file=${lib.escapeShellArg guardCurrentFile}
    exec 9>"$guard_file.lock"
    ${pkgs.util-linux}/bin/flock -x 9
    if [ -r "$guard_file" ] && [ "$(${pkgs.coreutils}/bin/cat "$guard_file")" = "$1" ]; then
      ${pkgs.coreutils}/bin/rm -f "$guard_file"
    fi
  '';
  rollbackWithGuard = pkgs.writeShellScript "nas-v2-rollback-with-guard" ''
    set -euo pipefail
    guard_file=${lib.escapeShellArg guardCurrentFile}
    guard_unit=""
    if [ -r "$guard_file" ]; then
      guard_unit="$(${pkgs.util-linux}/bin/flock -s "$guard_file.lock" ${pkgs.coreutils}/bin/cat "$guard_file" 2>/dev/null || true)"
    fi
    if [ -n "$guard_unit" ]; then
      recovery_timeout=600
      if [ -r ${lib.escapeShellArg budgetFile} ]; then
        if observed_timeout="$(${pkgs.jq}/bin/jq -er '.transactionSeconds | select(type == "number" and . >= 0 and floor == .) | . + 30 | if . < 600 then 600 else . end' ${lib.escapeShellArg budgetFile} 2>/dev/null)" \
          && [[ "$observed_timeout" =~ ^[0-9]+$ ]]; then
          recovery_timeout="$observed_timeout"
        fi
      fi
      if ${v2Python}/bin/python ${v2Source}/nas_guarded_apply.py \
        --state-dir ${lib.escapeShellArg guardStateDir} \
        --systemctl ${lib.escapeShellArg "${pkgs.systemd}/bin/systemctl"} \
        --unit "$guard_unit" \
        fired --rollback-timeout "$recovery_timeout" -- ${rollbackToApplied}; then
        ${clearGuardCurrent} "$guard_unit"
        exit 0
      else
        status=$?
        ${clearGuardCurrent} "$guard_unit"
        exit $status
      fi
    fi
    exec ${rollbackToApplied}
  '';
  guardUnitShell = ''
    guard_suffix="$(printf '%s' "$INVOCATION_ID" | ${pkgs.coreutils}/bin/tr -d '-' | ${pkgs.coreutils}/bin/cut -c1-12)"
    test -n "$guard_suffix"
    guard_unit="nas-v2-apply-rollback-$guard_suffix"
  '';
in
{
  config = {
    systemd.tmpfiles.rules = [
      "d ${guardStateDir} 0755 root root -"
    ];
    # The compiler records the exact desired revision while holding the same
    # authority lock used to parse services.yaml. These environment variables
    # opt the production entry point into that history transaction.
    systemd.services.nas-managed-services-reconcile.environment.NAS_V2_HISTORY_REPOSITORY = historyRepoPath;
    systemd.services.nas-managed-services-reconcile.environment.NAS_V2_GIT_BIN = "${pkgs.git}/bin/git";
    systemd.services.nas-managed-services-reconcile.environment.NAS_V2_APPLY_BUDGET = budgetFile;

    # Convert edge-triggered services.yaml notifications into a level-triggered
    # pending marker. systemd.path rechecks PathExists when the oneshot exits,
    # so an edit that arrives while reconciliation is active cannot be lost.
    systemd.services.nas-managed-services-dirty = {
      description = "Queue Managed Services V2 desired-state reconciliation";
      serviceConfig = {
        Type = "oneshot";
        # ConditionPathExists is evaluated before ExecStart, so readiness can
        # disappear between the gate and the touch. Recheck readiness under the
        # same exclusive lock the secret transaction holds so a start cannot
        # write reconcile.pending after readiness is removed.
        ExecStart = "${pkgs.util-linux}/bin/flock -x /run/lock/nas-secrets.lock ${pkgs.bash}/bin/bash -c 'if test -e ${nasInternal.secretRoot}/ready; then exec ${pkgs.coreutils}/bin/touch ${reconcilePendingPath}; fi'";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/run/nas-control" "/run/lock" ];
      };
    };
    systemd.paths.nas-managed-services-dirty = {
      description = "Notice Managed Services V2 desired-state changes";
      wantedBy = [ "nas-protected-services.target" ];
      partOf = [ "nas-protected-services.target" ];
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
      # Establish a real pre-mutation applied revision before the guard can
      # observe a first-boot failure. The Python entrypoint repeats this check
      # under the authority lock before committing the desired revision.
      ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} bootstrap
      ${guardUnitShell}
      ${pkgs.coreutils}/bin/mkdir -p ${lib.escapeShellArg guardStateDir}
      ${v2Python}/bin/python ${v2Source}/nas_v2_apply_budget.py \
        --desired ${lib.escapeShellArg desiredPath} \
        --state ${lib.escapeShellArg systemdStatePath} \
        --output ${lib.escapeShellArg budgetFile}
      guard_timeout="$(${pkgs.jq}/bin/jq -er '.transactionSeconds' ${lib.escapeShellArg budgetFile})"
      (
        ${pkgs.util-linux}/bin/flock -x 9
        ${pkgs.coreutils}/bin/printf '%s' "$guard_unit" > ${lib.escapeShellArg guardCurrentFile}
      ) 9>${lib.escapeShellArg "${guardCurrentFile}.lock"}
      ${v2Python}/bin/python ${v2Source}/nas_guarded_apply.py \
        --unit "$guard_unit" \
        --systemctl ${lib.escapeShellArg "${pkgs.systemd}/bin/systemctl"} \
        --state-dir ${lib.escapeShellArg guardStateDir} \
        arm \
        --timeout "$guard_timeout" \
        --systemd-run ${lib.escapeShellArg "${pkgs.systemd}/bin/systemd-run"} \
        -- ${rollbackToApplied}
    '';

    # A normal failure gets the same rollback immediately; the transient timer
    # remains the crash/deadlock fallback when systemd never reaches OnFailure.
    # The failed unit claims the durable guard so the later timer firing
    # observes the terminal outcome instead of duplicating rollback.
    systemd.services.nas-managed-services-reconcile.onFailure = lib.mkAfter [
      "nas-v2-apply-failed.service"
    ];
    systemd.services.nas-v2-apply-failed = {
      description = "Restore the last applied Managed Services V2 desired state";
      # Dependency failure before preStart is not a failed apply transaction.
      unitConfig.ConditionPathExists = guardCurrentFile;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = rollbackWithGuard;
      };
    };

    # Native subsystem projections participate in one guarded finite apply.
    # nmstate owns host VLAN/VRF state, firewalld owns its permanent policy
    # objects, systemd/Quadlet own process/container activation, and Caddy's
    # own Admin API transaction owns live route replacement.
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

      # When Caddy is already running, load the complete current active config
      # directly through Caddy's native Admin API client. If Caddy has not
      # started yet (bootstrap), it will read the newly generated import when it
      # starts, so no deferred V2 reload unit is necessary.
      if ${pkgs.systemd}/bin/systemctl is-active --quiet caddy.service; then
        ${caddyPackage}/bin/caddy reload \
          --config ${lib.escapeShellArg caddyActivePath} \
          --adapter caddyfile \
          --force
      fi

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
        --state-dir ${lib.escapeShellArg guardStateDir} \
        cancel
      ${clearGuardCurrent} "$guard_unit"
      ${v2Python}/bin/python ${lib.escapeShellArgs historyArgs} clear-previous-applied
    '';

    # Superseded by the generic transaction and direct native Caddy reload.
    systemd.services.nas-v2-firewall-rollback.enable = lib.mkForce false;
    systemd.timers.nas-v2-firewall-rollback.enable = lib.mkForce false;
    systemd.services.nas-managed-services-caddy-reload.enable = lib.mkForce false;
    systemd.paths.nas-managed-services-caddy-reload.enable = lib.mkForce false;
  };
}
