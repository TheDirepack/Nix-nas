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

export function api(args, spawn = globalThis.cockpit?.spawn) {
  return requireSpawn(spawn)(["nas-cockpit-api", ...args], {
    superuser: "require",
    err: "message",
  }).then(parseJsonOutput);
}

export function apiInput(args, payload, spawn = globalThis.cockpit?.spawn) {
  const process = requireSpawn(spawn)(["nas-cockpit-api", ...args], {
    superuser: "require",
    err: "message",
  });
  process.input(JSON.stringify(payload));
  return process.then(parseJsonOutput);
}

export function managedServicesDocument(spawn = globalThis.cockpit?.spawn) {
  return requireSpawn(spawn)(["nas-managed-services-control", "document"], {
    superuser: "require",
    err: "message",
  }).then(parseJsonOutput);
}

export function replaceManagedServicesDocument(yaml, spawn = globalThis.cockpit?.spawn) {
  if (typeof yaml !== "string" || yaml.length === 0) {
    throw new Error("Managed Services V2 YAML must not be empty.");
  }
  const process = requireSpawn(spawn)(["nas-managed-services-control", "replace-document", "-"], {
    superuser: "require",
    err: "message",
  });
  process.input(yaml);
  return process.then(parseJsonOutput);
}

export function replaceManagedServicesJsonDocument(document, spawn = globalThis.cockpit?.spawn) {
  if (document === null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("Managed Services V2 schema editor value must be an object.");
  }
  const process = requireSpawn(spawn)(
    ["nas-managed-services-control", "replace-json-document", "-"],
    {
      superuser: "require",
      err: "message",
    },
  );
  process.input(JSON.stringify(document));
  return process.then(parseJsonOutput);
}

export function managedServicesStatus(spawn = globalThis.cockpit?.spawn) {
  return requireSpawn(spawn)(["nas-managed-services-control", "status"], {
    superuser: "require",
    err: "message",
  }).then(parseJsonOutput);
}

export function setManagedServiceMode(serviceId, mode, spawn = globalThis.cockpit?.spawn) {
  if (typeof serviceId !== "string" || !/^[a-z][a-z0-9-]{0,63}$/.test(serviceId)) {
    throw new Error("Invalid Managed Services V2 service identifier.");
  }
  if (!new Set(["off", "on-demand", "always"]).has(mode)) {
    throw new Error("Invalid Managed Services V2 service mode.");
  }
  return requireSpawn(spawn)(["nas-managed-services-control", "set", serviceId, mode], {
    superuser: "require",
    err: "message",
  }).then(parseJsonOutput);
}

export function startFirstRun(
  password,
  administrator,
  options = {},
  spawn = globalThis.cockpit?.spawn,
) {
  const secret = singleLinePassword(password);
  if (!administrator || typeof administrator !== "object") {
    throw new Error("Enter the administrator details.");
  }
  const {username, name, email, password: administratorPassword} = administrator;
  if (
    ![username, name, email, administratorPassword].every(
      (value) => typeof value === "string" && value.length > 0,
    )
  ) {
    throw new Error("Complete every administrator field.");
  }
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(username)) {
    throw new Error("Administrator username is invalid.");
  }
  if (
    [name, email, administratorPassword].some(
      (value) => value.includes("\n") || value.includes("\r"),
    )
  ) {
    throw new Error("Administrator details must be single-line values.");
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error("Administrator email is invalid.");
  }
  if (administratorPassword.length < 12) {
    throw new Error("Administrator password must contain at least 12 characters.");
  }
  if (typeof options.planDigest !== "string" || !/^[0-9a-f]{64}$/.test(options.planDigest)) {
    throw new Error("Refresh and review the current first-start plan before continuing.");
  }
  const devices = Array.isArray(options.devices) ? options.devices : [];
  if (!devices.every((value) => typeof value === "string" && value.length > 0)) {
    throw new Error("First-start storage devices are invalid.");
  }
  return apiInput(
    ["first-start"],
    {
      password: secret,
      administrator: {username, name, email, password: administratorPassword},
      planDigest: options.planDigest,
      devices,
      allowDestructiveStorage: options.allowDestructiveStorage === true,
      confirmPasswordReapply: options.confirmPasswordReapply === true,
    },
    spawn,
  );
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
