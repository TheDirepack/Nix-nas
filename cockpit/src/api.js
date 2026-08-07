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

export function startFirstRun(password, options = {}, spawn = globalThis.cockpit?.spawn) {
  const secret = singleLinePassword(password);
  if (typeof options.planDigest !== "string" || !/^[0-9a-f]{64}$/.test(options.planDigest)) {
    throw new Error("Refresh and review the current first-start plan before continuing.");
  }
  const args = ["nas-cockpit-api", "first-run", "--plan-digest", options.planDigest];
  if (options.allowDestructiveStorage) args.push("--allow-destructive-storage");
  if (options.confirmPasswordReapply) args.push("--confirm-password-reapply");
  const process = requireSpawn(spawn)(args, {superuser: "require", err: "message"});
  process.input(`${secret}\n`);
  return process.then(parseJsonOutput);
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
