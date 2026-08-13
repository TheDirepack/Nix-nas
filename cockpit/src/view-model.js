export const MODE_LABELS = {
  off: "Off",
  "on-demand": "On demand",
  always: "Always on",
};

export const LINK_LABELS = {
  identity: "Identity (Authentik)",
  accountSettings: "My account settings",
  docs: "NAS help",
  copypartyConfig: "CopyParty settings",
  files: "Host files",
  storage: "ZFS storage",
  containers: "Containers",
  virtualMachines: "Virtual machines",
  network: "Network and firewall",
  power: "Power",
  logs: "System logs",
  softwareUpdates: "Software updates",
  terminal: "Terminal",
  scheduler: "Schedules",
};

export const OPERATIONS = [
  ["identity-sync", "Validate identity model"],
  ["health", "Run system health checks"],
  ["snapshot", "Create ZFS snapshot"],
  ["zfs-scrub", "Start ZFS scrub"],
  ["backup", "Run system backup"],
  ["replicate", "Replicate ZFS now"],
  ["syncthing-sync", "Reconcile Syncthing"],
  ["update-preview", "Preview approved updates"],
  ["update-sync", "Sync approved updates"],
  ["update-apply", "Apply validated update"],
  ["protected-restart", "Restart protected services"],
];

export function managedServiceMap(data = {}) {
  const services = Array.isArray(data?.managedServices?.services)
    ? data.managedServices.services
    : [];
  return Object.fromEntries(
    services
      .filter(
        (service) =>
          service && typeof service === "object" && typeof service.id === "string" && service.id,
      )
      .map((service) => [service.id, service]),
  );
}

export function managedServiceRows(data = {}) {
  return Object.values(managedServiceMap(data)).sort((left, right) =>
    String(left.label || left.id).localeCompare(String(right.label || right.id)),
  );
}

export function inactiveServiceCount(services = {}) {
  const rows = Array.isArray(services) ? services : Object.values(services || {});
  return rows.filter((item) => {
    if (!item || typeof item !== "object") return false;
    if (typeof item.activeState === "string") return item.activeState !== "active";
    return item.active !== true;
  }).length;
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

export function staticLinks(data = {}) {
  const links =
    data?.links && typeof data.links === "object" && !Array.isArray(data.links) ? data.links : {};
  return Object.entries(links)
    .map(([key, url]) => ({key, label: LINK_LABELS[key] || key, url: safeInternalPath(url)}))
    .filter((entry) => entry.url);
}

export function managedApplicationLinks(data = {}) {
  const entries = Array.isArray(data?.managedServiceLinks) ? data.managedServiceLinks : [];
  return entries
    .filter(
      (entry) =>
        entry &&
        typeof entry === "object" &&
        typeof entry.id === "string" &&
        typeof entry.label === "string" &&
        typeof entry.url === "string" &&
        safeInternalPath(entry.url),
    )
    .map((entry) => ({
      ...entry,
      url: safeInternalPath(entry.url),
      category: typeof entry.category === "string" && entry.category ? entry.category : "Other",
      order: Number.isFinite(entry.order) ? entry.order : 0,
    }))
    .sort(
      (left, right) =>
        left.order - right.order ||
        left.category.localeCompare(right.category) ||
        left.label.localeCompare(right.label),
    );
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
      serviceCount: 0,
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
    serviceCount: Number(firstStart.serviceCount || 0),
    destructiveRequired: firstStart.requiresDestructiveConfirmation === true,
    journal:
      setup.setupJournal && typeof setup.setupJournal === "object" ? setup.setupJournal : null,
    authorityHealth: firstStart.authorityHealth || null,
  };
}

export function managedServiceUnitState(service = {}) {
  service = service && typeof service === "object" && !Array.isArray(service) ? service : {};
  const units = Array.isArray(service.units) ? service.units : [];
  if (!units.length) return service.managed === false ? "Platform service" : "No native unit";
  const active = units.filter(
    (unit) => unit?.active === true || unit?.activeState === "active",
  ).length;
  if (active === units.length) return "Running";
  return active
    ? "Partially running"
    : service.effectiveMode === "on-demand"
      ? "Sleeping"
      : "Stopped";
}

export function managedServiceRuntimeText(service = {}) {
  service = service && typeof service === "object" && !Array.isArray(service) ? service : {};
  const details = [];
  if (service.managed === false) details.push("Lifecycle remains native to the platform");
  if (service.runtimeAvailable === false) details.push("Runtime unavailable");
  if (service.effectiveMode === "on-demand" && service.running)
    details.push("Native idle lease active");
  else if (service.effectiveMode === "on-demand")
    details.push("Starts on authorized access or explicit wake");
  if (Number.isFinite(service.idleSeconds) && service.effectiveMode === "on-demand") {
    details.push(`Idle policy ${Math.ceil(service.idleSeconds / 60)} min`);
  }
  return details.join(" · ");
}

export function operationBusy(data = {}, actionId = "") {
  const busy = new Set(
    Array.isArray(data?.operations?.busyClasses) ? data.operations.busyClasses : [],
  );
  const conflicts = data?.operations?.conflictsByAction?.[actionId];
  if (!Array.isArray(conflicts)) return busy.size > 0;
  return conflicts.some((item) => busy.has(item));
}

export function managedServiceOperationsBusy(data = {}) {
  const busy = new Set(
    Array.isArray(data?.operations?.busyClasses) ? data.operations.busyClasses : [],
  );
  const conflicts = Array.isArray(data?.operations?.managedServicesConflicts)
    ? data.operations.managedServicesConflicts
    : ["runtime", "appliance", "first-start"];
  return conflicts.some((item) => busy.has(item));
}

export function visibleOperations(data = {}) {
  const services = managedServiceMap(data);
  return OPERATIONS.filter(([id]) => {
    if (id === "backup")
      return Boolean(services.backups?.available ?? services.backup?.available ?? true);
    if (id === "replicate") return data?.zfsReplicationInstalled === true;
    if (id === "syncthing-sync") return Boolean(services.syncthing?.available ?? true);
    return true;
  });
}

export function mib(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  return (bytes / 1048576).toFixed(bytes < 104857600 ? 1 : 0);
}
