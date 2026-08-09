export const CAPABILITIES = [
  ["files", "Files"],
  ["webdav", "WebDAV"],
  ["ai", "AI UI"],
  ["vault", "Vault SSO"],
];

export const MODE_LABELS = {
  off: "Off",
  "on-demand": "On demand",
  always: "Always on",
};

export const LINK_LABELS = {
  identity: "Identity (Authentik)",
  settings: "My account settings",
  documentation: "NAS help",
  shares: "Files (CopyParty)",
  copypartyConfig: "CopyParty settings",
  aiWorkspace: "AI workspace",
  aiRuntime: "AI runtime",
  syncthing: "Syncthing",
  vaultwarden: "Vaultwarden",
  files: "Host files",
  zfs: "ZFS storage",
  podman: "Containers",
  machines: "Virtual machines",
  network: "Network and firewall",
  ups: "UPS",
  alerts: "Alerts",
  metrics: "Grafana dashboards",
  notifications: "Notifications",
  victoriaMetrics: "Metrics explorer",
  scheduler: "Schedules",
};

export const OPERATIONS = [
  ["identity-sync", "Validate identity model"],
  ["health", "Run system health checks"],
  ["snapshot", "Create ZFS snapshots"],
  ["scrub", "Start ZFS scrub"],
  ["backup", "Run system backup"],
  ["syncthing-reconcile", "Reconcile Syncthing"],
  ["update-preview", "Preview and validate updates"],
  ["update-sync", "Sync and validate approved updates"],
  ["update-apply", "Deploy validated checkout"],
  ["protected-restart", "Restart protected services"],
];

export function featureMap(data = {}) {
  const features = Array.isArray(data?.featureControl?.features)
    ? data.featureControl.features
    : [];
  return Object.fromEntries(
    features
      .filter(
        (feature) =>
          feature && typeof feature === "object" && typeof feature.id === "string" && feature.id,
      )
      .map((feature) => [feature.id, feature]),
  );
}

export function inactiveServiceCount(services = []) {
  const rows = Array.isArray(services) ? services : [];
  return rows.filter(
    (item) =>
      item &&
      typeof item === "object" &&
      item.active !== "active" &&
      !String(item.unit || "").endsWith(".timer"),
  ).length;
}

export function revisionModel(update = {}) {
  update = update && typeof update === "object" && !Array.isArray(update) ? update : {};
  if (update.ok === false) return {kind: "error", error: update.error || "Unknown error"};
  const divergence =
    Number.isInteger(update.ahead) && Number.isInteger(update.behind)
      ? `${update.ahead} ahead / ${update.behind} approved update${update.behind === 1 ? "" : "s"} available`
      : "Upstream status unavailable until a tracking branch is configured";
  const checkout = update.dirty === true ? "dirty" : update.dirty === false ? "clean" : "unknown";
  return {
    kind: "status",
    revision: update.revision || "unknown",
    branch: update.branch || "unknown",
    upstream: update.upstream || "not configured",
    divergence,
    checkout,
  };
}

export function safeInternalPath(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) return null;
  if (
    [...value].some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127;
    })
  )
    return null;
  return value;
}

export function enabledLinkKeys(data = {}) {
  const features = featureMap(data);
  const enabled = {
    identity: true,
    settings: true,
    documentation: true,
    shares: true,
    copypartyConfig: true,
    files: true,
    zfs: true,
    podman: true,
    network: true,
    scheduler: true,
    aiWorkspace: Boolean(features.aiWorkspace?.effective),
    aiRuntime: Boolean(features.aiRuntime?.effective),
    syncthing: Boolean(features.syncthing?.effective),
    vaultwarden: Boolean(features.vaultwarden?.effective),
    machines: Boolean(features.virtualization?.effective),
    ups: Boolean(features.upsWeb?.effective),
    alerts: Boolean(features.alerts?.effective),
    victoriaMetrics: Boolean(features.observability?.effective),
    metrics: Boolean(features.grafana?.effective),
    notifications: Boolean(features.notifications?.effective),
  };
  const links =
    data?.links && typeof data.links === "object" && !Array.isArray(data.links) ? data.links : {};
  return Object.keys(links).filter((key) => Boolean(enabled[key]));
}

export function setupModel(data = {}) {
  data = data && typeof data === "object" && !Array.isArray(data) ? data : {};
  const setup = data.setup;
  if (!setup || typeof setup !== "object") {
    return {
      complete: false,
      verified: false,
      pending: true,
      ready: false,
      status: "unknown",
      message:
        "First-start state is unavailable. Recheck the configuration or inspect the setup service.",
      configPath: "",
      planDigest: "",
      storage: {},
      accountCount: 0,
      featureCount: 0,
      destructiveRequired: false,
      journal: null,
    };
  }
  const firstStart =
    setup.firstStart && typeof setup.firstStart === "object" ? setup.firstStart : {};
  const stateStatus = setup.setupState?.status;
  const status = firstStart.status || stateStatus || "unknown";
  const complete = status === "complete" || status === "complete-unverified";
  return {
    complete,
    verified: status === "complete",
    pending: !complete,
    ready: status === "ready",
    status,
    message: firstStart.message || setup.error || "First-start state is unavailable.",
    configPath: firstStart.configPath || "",
    planDigest: firstStart.planDigest || setup.setupState?.planDigest || "",
    storage: firstStart.storage || {},
    accountCount: Number(firstStart.accountCount || 0),
    featureCount: Number(firstStart.featureCount || 0),
    destructiveRequired: firstStart.requiresDestructiveConfirmation === true,
    journal:
      setup.setupJournal && typeof setup.setupJournal === "object" ? setup.setupJournal : null,
    authorityHealth: firstStart.authorityHealth || null,
  };
}

export function featureUnitState(feature = {}) {
  feature = feature && typeof feature === "object" && !Array.isArray(feature) ? feature : {};
  const units = Array.isArray(feature?.units) ? feature.units : [];
  if (!units.length) return "Logical group";
  const active = units.filter((unit) => unit.active).length;
  if (active === units.length) return "Running";
  return active ? "Partially running" : "Sleeping";
}

export function featureRuntimeText(feature = {}) {
  feature = feature && typeof feature === "object" && !Array.isArray(feature) ? feature : {};
  const details = [];
  if (feature.runtimeAvailable === false) {
    details.push(`Runtime unavailable: ${feature.availabilityReason || "probe failed"}`);
  }
  if (feature.effectiveMode === "on-demand" && feature.running) {
    details.push(
      `Idle stop in ${feature.idleRemainingSeconds == null ? "—" : `${Math.ceil(feature.idleRemainingSeconds / 60)} min`}`,
    );
  } else if (feature.effectiveMode === "on-demand") {
    details.push("Starts on first authorized access");
  }
  if (Number.isFinite(feature.lastStartDurationMs)) {
    details.push(`Last cold start ${(feature.lastStartDurationMs / 1000).toFixed(1)}s`);
  }
  if (feature.startupEstimateSeconds) {
    details.push(
      `Expected warm ${feature.startupEstimateSeconds.warm}s; first ${feature.startupEstimateSeconds.first}s`,
    );
  }
  if (Array.isArray(feature.heldBy) && feature.heldBy.length)
    details.push(`Kept resident by ${feature.heldBy.join(", ")}`);
  return details.join(" · ");
}

export function operationConflicts(data = {}, actionId) {
  const value = data?.operationState?.conflictsByAction?.[actionId];
  return Array.isArray(value) ? value : [];
}

export function operationBusy(data = {}, actionId) {
  const busy = new Set(
    Array.isArray(data?.operationState?.busyClasses) ? data.operationState.busyClasses : [],
  );
  return operationConflicts(data, actionId).some((item) => busy.has(item));
}

export function featureOperationsBusy(data = {}) {
  const busy = new Set(
    Array.isArray(data?.operationState?.busyClasses) ? data.operationState.busyClasses : [],
  );
  const conflicts = Array.isArray(data?.operationState?.featureConflicts)
    ? data.operationState.featureConflicts
    : ["runtime"];
  return conflicts.some((item) => busy.has(item));
}

export function visibleOperations(data = {}) {
  const features = featureMap(data);
  return OPERATIONS.filter(([id]) => {
    if (id === "backup") return Boolean(features.backups?.available);
    if (id === "syncthing-reconcile") return Boolean(features.syncthing?.available);
    return true;
  });
}

export function mib(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  return (bytes / 1048576).toFixed(bytes < 104857600 ? 1 : 0);
}
