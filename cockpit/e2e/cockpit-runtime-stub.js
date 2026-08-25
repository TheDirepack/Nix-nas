globalThis.cockpit = globalThis.cockpit || {};

// The production bundle keeps the Cockpit host module external. Resolve that
// module through the injected browser fixture when the bundle runs standalone.
if (typeof globalThis.require !== "function") {
  globalThis.require = (name) => {
    if (name === "cockpit") return globalThis.cockpit;
    throw new Error(`Unsupported standalone Cockpit module: ${name}`);
  };
}
