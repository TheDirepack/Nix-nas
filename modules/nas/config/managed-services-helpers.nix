{ lib, config, nasInternal }:
let
  cfg = config.nas;
  v2Ports = import ../internal/v2-ports.nix { inherit lib config; };
in
rec {
  inherit (v2Ports) syncthingGuiPort syncthingSyncPort syncthingDiscoveryPort vaultwardenPort nutUpsdPort;

  durationSeconds = value:
    let
      matched = builtins.match "^([0-9]+)(s|sec|min|m|h|d|w)$" value;
      amount = if matched == null then null else lib.toInt (builtins.elemAt matched 0);
      unit = if matched == null then null else builtins.elemAt matched 1;
      multiplier = {
        s = 1;
        sec = 1;
        min = 60;
        m = 60;
        h = 3600;
        d = 86400;
        w = 604800;
      }.${if unit == null then "s" else unit};
      seconds = if amount == null then 0 else amount * multiplier;
    in
      if matched == null || seconds < 60 then
        throw "nas.identity.syncInterval must be a whole-unit duration of at least 60 seconds for Managed Services V2 (for example 5min, 1h, or 1d)"
      else
        seconds;

  syncSchedules = lib.optionals (cfg.scheduler.backend == "systemd") [
    {
      intervalSeconds = durationSeconds cfg.identity.syncInterval;
      randomizedDelaySeconds = 0;
      persistent = false;
    }
  ];

  daemon = unit: name: {
    inherit name;
    managed = true;
    workload = { kind = "daemon"; activation = "persistent"; };
    runtime = { type = "systemd"; inherit unit; };
  };
  onDemand = unit: name: idleSeconds: (daemon unit name) // {
    workload = { kind = "daemon"; activation = "on-demand"; inherit idleSeconds; };
  };
  job = unit: name: {
    inherit name;
    managed = true;
    workload.kind = "job";
    runtime = { type = "systemd"; inherit unit; };
  };
  scheduledJob = unit: name: schedules: (job unit name) // {
    workload = { kind = "job"; inherit schedules; };
  };
  platformService = service: service // { managed = false; };
  depends = service: condition: { inherit service condition; };
  dependency = depends;
  operationDependency = depends;
  pathRoute = paths: target: auth: {
    inherit target auth;
    exposure = { type = "path"; inherit paths; };
  };
  httpTarget = port: { type = "http"; host = "127.0.0.1"; inherit port; };
  copypartyTarget = { type = "unix-http"; socket = "/run/copyparty/http.sock"; };
  identity = capability: { mode = "identity"; inherit capability; };
  capability = id: title: { inherit id title; };
  adminCapability = title: [ (capability "admin" title) ];
  portal = title: category: icon: order: {
    visible = true;
    inherit title category icon order;
  };
  portListener = protocol: port: {
    inherit protocol;
    exposure = { inherit port; };
    firewall = true;
  };

  operationJob = scheduledJob;
  calendar = expression: randomizedDelaySeconds: {
    calendar = expression;
    inherit randomizedDelaySeconds;
    persistent = true;
  };
  operationCalendar = calendar;
  systemdSchedules = schedules: lib.optionals (cfg.scheduler.backend == "systemd") schedules;
  operationSystemdSchedules = systemdSchedules;
  healthSchedule = systemdSchedules [ (calendar "*-*-* 06:00" 1800) ];
  operationHealthSchedule = healthSchedule;

  backupStage = cfg.backup.stagingPath;
  nativeDumpStagingRoot = "/run/nas-control/backup-staging";
  authentikArtifact = "${nativeDumpStagingRoot}/authentik-database";
  copypartyArtifact = "${nativeDumpStagingRoot}/copyparty-databases";
  vaultwardenArtifact = "${nativeDumpStagingRoot}/vaultwarden-data";
  vaultwardenDataDir = nasInternal.vaultwardenDataDir;
  vaultwardenBackupDir = nasInternal.vaultwardenBackupDir;
  copypartyDataDir = nasInternal.copypartyDataDir;
}
