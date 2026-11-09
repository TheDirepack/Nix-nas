function requireSpawn(spawn) {
  if (typeof spawn !== "function") throw new Error("Cockpit process API is unavailable.");
  return spawn;
}

function singleLinePassword(password) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Enter the KeePassXC database password.");
  }
  if (password.includes("\n") || password.includes("\r")) {
    throw new Error("The KeePassXC database password must be a single line.");
  }
  return password;
}

export function parseJsonOutput(output) {
  return JSON.parse(output);
}

function jsonResult(process) {
  // Cockpit Deferred callbacks do not turn thrown parse errors into rejections.
  return Promise.resolve(process).then(parseJsonOutput);
}

function sha256(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest.`);
  }
  return value;
}

export function api(args, spawn = globalThis.cockpit?.spawn) {
  const process = requireSpawn(spawn)(["nas-cockpit-api", ...args], {
    superuser: "require",
    err: "message",
  });
  return jsonResult(process);
}

export function apiInput(args, payload, spawn = globalThis.cockpit?.spawn) {
  const process = requireSpawn(spawn)(["nas-cockpit-api", ...args], {
    superuser: "require",
    err: "message",
  });
  process.input(JSON.stringify(payload));
  return jsonResult(process);
}

export function managedServicesDocument(spawn = globalThis.cockpit?.spawn) {
  const process = requireSpawn(spawn)(["nas-managed-services-control", "document"], {
    superuser: "require",
    err: "message",
  });
  return jsonResult(process);
}

export function replaceManagedServicesDocument(yaml, revision, spawn = globalThis.cockpit?.spawn) {
  if (typeof yaml !== "string" || yaml.length === 0) {
    throw new Error("Managed Services V2 YAML must not be empty.");
  }
  const process = requireSpawn(spawn)(
    ["nas-managed-services-control", "replace-document", "-", sha256(revision, "Revision")],
    {
      superuser: "require",
      err: "message",
    },
  );
  process.input(yaml);
  return jsonResult(process);
}

export function replaceManagedServicesJsonDocument(
  document,
  revision,
  spawn = globalThis.cockpit?.spawn,
) {
  if (document === null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("Managed Services V2 schema editor value must be an object.");
  }
  const process = requireSpawn(spawn)(
    ["nas-managed-services-control", "replace-json-document", "-", sha256(revision, "Revision")],
    {
      superuser: "require",
      err: "message",
    },
  );
  process.input(JSON.stringify(document));
  return jsonResult(process);
}

export function setManagedServiceMode(serviceId, mode, spawn = globalThis.cockpit?.spawn) {
  if (typeof serviceId !== "string" || !/^[a-z][a-z0-9-]{0,63}$/.test(serviceId)) {
    throw new Error("Invalid Managed Services V2 service identifier.");
  }
  if (!new Set(["off", "on-demand", "always"]).has(mode)) {
    throw new Error("Invalid Managed Services V2 service mode.");
  }
  const process = requireSpawn(spawn)(["nas-managed-services-control", "set", serviceId, mode], {
    superuser: "require",
    err: "message",
  });
  return jsonResult(process);
}

export function activateSecrets(password, spawn = globalThis.cockpit?.spawn) {
  const secret = singleLinePassword(password);
  const process = requireSpawn(spawn)(["nas-secrets", "activate-stdin"], {
    superuser: "require",
    err: "message",
  });
  process.input(`${secret}\n`);
  return process;
}
