import cockpit from "cockpit";

const SYSTEMD_NAME = "org.freedesktop.systemd1";
const MANAGER_PATH = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE = "org.freedesktop.systemd1.Manager";
const PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties";
const UNIT_INTERFACE = "org.freedesktop.systemd1.Unit";

function onlyReturnValue(reply) {
  return Array.isArray(reply) && reply.length === 1 ? reply[0] : reply;
}

function unitFromListRow(row) {
  if (!Array.isArray(row) || row.length < 7 || typeof row[0] !== "string") return null;
  return {
    unit: row[0],
    description: typeof row[1] === "string" ? row[1] : "",
    loadState: typeof row[2] === "string" ? row[2] : "unknown",
    activeState: typeof row[3] === "string" ? row[3] : "unknown",
    subState: typeof row[4] === "string" ? row[4] : "unknown",
    objectPath: typeof row[6] === "string" ? row[6] : "",
  };
}

async function memoryCurrent(client, objectPath) {
  if (!objectPath) return null;
  try {
    const reply = await client.call(
      objectPath,
      PROPERTIES_INTERFACE,
      "Get",
      [UNIT_INTERFACE, "MemoryCurrent"],
    );
    const variant = onlyReturnValue(reply);
    const value = variant && typeof variant === "object" ? variant.v : null;
    return Number.isFinite(value) && value >= 0 ? value : null;
  } catch (_error) {
    return null;
  }
}

async function listUnits(client, method, args) {
  const reply = await client.call(MANAGER_PATH, MANAGER_INTERFACE, method, args);
  const rows = onlyReturnValue(reply);
  return Array.isArray(rows) ? rows.map(unitFromListRow).filter(Boolean) : [];
}

export function managedServiceUnitNames(data = {}) {
  const services = Array.isArray(data?.managedServices?.services)
    ? data.managedServices.services
    : [];
  return [
    ...new Set(
      services.flatMap((service) =>
        Array.isArray(service?.units)
          ? service.units
              .map((unit) => unit?.unit)
              .filter((unit) => typeof unit === "string" && unit)
          : [],
      ),
    ),
  ];
}

export async function readSystemdState(unitNames = []) {
  const client = cockpit.dbus(SYSTEMD_NAME, {bus: "system"});
  try {
    const names = [...new Set(unitNames.filter((name) => typeof name === "string" && name))];
    const namedPromise = names.length
      ? listUnits(client, "ListUnitsByNames", [names])
      : Promise.resolve([]);
    const failedPromise = listUnits(client, "ListUnitsByPatterns", [["failed"], []]);
    const [namedUnits, failedUnits] = await Promise.all([namedPromise, failedPromise]);
    const hydrated = await Promise.all(
      namedUnits.map(async (unit) => ({
        ...unit,
        active: unit.activeState === "active",
        memoryBytes: await memoryCurrent(client, unit.objectPath),
      })),
    );
    return {
      units: Object.fromEntries(hydrated.map((unit) => [unit.unit, unit])),
      failedUnits: failedUnits.map(
        (unit) => `${unit.unit} ${unit.loadState} ${unit.activeState} ${unit.subState} ${unit.description}`.trim(),
      ),
    };
  } finally {
    client.close();
  }
}

export function mergeSystemdState(data = {}, snapshot = {}) {
  const unitState = snapshot?.units && typeof snapshot.units === "object" ? snapshot.units : {};
  const managedServices =
    data?.managedServices && typeof data.managedServices === "object"
      ? data.managedServices
      : {services: []};
  const services = Array.isArray(managedServices.services)
    ? managedServices.services.map((service) => {
        const units = Array.isArray(service?.units)
          ? service.units.map((unit) => ({...unit, ...(unitState[unit?.unit] || {})}))
          : [];
        const running = units.some((unit) => unit.activeState === "active" || unit.active === true);
        const effectiveMode = service?.effectiveMode;
        const healthy = Boolean(service?.effective) && running;
        return {
          ...service,
          units,
          running,
          resident: effectiveMode === "always",
          healthState: healthy ? "healthy" : "inactive",
          healthy,
        };
      })
    : [];
  return {
    ...data,
    services: unitState,
    failedUnits: Array.isArray(snapshot?.failedUnits) ? snapshot.failedUnits : data?.failedUnits || [],
    managedServices: {...managedServices, services},
  };
}
