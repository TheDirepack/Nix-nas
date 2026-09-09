#!/usr/bin/env node
import {copyFileSync, existsSync, mkdirSync, readFileSync, rmSync} from "node:fs";
import {join, resolve} from "node:path";
import {createRequire} from "node:module";
import process from "node:process";

const root = resolve(import.meta.dirname);
const source = join(root, "src");
const output = join(root, "dist");
const mode = process.argv[2] || "build";
const validModes = new Set(["build", "watch", "--watch", "check", "--check", "check-source", "--check-source"]);
if (!validModes.has(mode) || process.argv.length > 3) {
  console.error("Usage: node build.js [build|--watch|--check|--check-source]");
  process.exit(2);
}

// Source hashing and bundle verification are shared with the first-run
// wizard through scripts/frontend-build-integrity.cjs. The Nix sandbox
// overrides the location because only selected paths enter the store.
const require = createRequire(import.meta.url);
const integrity = require(
  process.env.NAS_FRONTEND_INTEGRITY_HELPER || join(root, "..", "scripts", "frontend-build-integrity.cjs"),
);

function files(directory) {
  return integrity.listFiles(directory);
}

function sourceHash() {
  const inputs = [...files(source), join(root, "package.json"), join(root, "build.js")];
  const lock = join(root, "package-lock.json");
  if (existsSync(lock)) inputs.push(lock);
  return integrity.sourceHash(root, inputs);
}

function fileDigest(path) {
  return integrity.fileDigest(path);
}

function outputRecords() {
  return integrity.outputRecords(output, ["README.md"]);
}

function verifyReferencedAssets() {
  for (const path of files(output).filter(item => item.endsWith(".css"))) {
    const css = readFileSync(path, "utf8");
    for (const match of css.matchAll(/url\((?:["']?)([^"')]+)(?:["']?)\)/g)) {
      const reference = match[1];
      if (/^(?:data:|https?:|#)/.test(reference)) continue;
      const resolved = resolve(path, "..", reference.split(/[?#]/, 1)[0]);
      if (!existsSync(resolved)) throw new Error(`Cockpit CSS references missing asset ${reference}`);
    }
  }
}

function sourceCheck() {
  const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const required = {
    "@patternfly/patternfly": "6.1.0",
    "@patternfly/react-core": "6.1.0",
    react: "18.3.1",
    "react-dom": "18.3.1",
  };
  for (const [name, version] of Object.entries(required)) {
    if (packageJson.dependencies?.[name] !== version) throw new Error(`${name} must be pinned to ${version}`);
  }
  const index = readFileSync(join(source, "index.jsx"), "utf8");
  const app = readFileSync(join(source, "app.jsx"), "utf8");
  if (!index.includes("createRoot") || !index.includes("@patternfly/patternfly/patternfly.css")) {
    throw new Error("Cockpit entry point is not a React/PatternFly entry point");
  }
  if (!app.includes('from "@patternfly/react-core"')) throw new Error("Cockpit application does not use PatternFly React");
  for (const forbidden of ["innerHTML", "document.querySelector", "document.createElement", "window.confirm"]) {
    if (app.includes(forbidden)) throw new Error(`Cockpit React application contains forbidden legacy DOM API: ${forbidden}`);
  }
  JSON.parse(readFileSync(join(source, "manifest.json"), "utf8"));
}

function copyAssets() {
  mkdirSync(output, {recursive: true});
  copyFileSync(join(source, "index.html"), join(output, "index.html"));
  copyFileSync(join(source, "manifest.json"), join(output, "manifest.json"));
}

async function build() {
  sourceCheck();
  if (!existsSync(join(root, "package-lock.json"))) {
    throw new Error("cockpit/package-lock.json is missing. Run npm ci before building an installable bundle.");
  }
  let esbuild;
  let sassPlugin;
  try {
    ({default: esbuild} = await import("esbuild"));
    ({sassPlugin} = await import("esbuild-sass-plugin"));
  } catch (error) {
    throw new Error(`Cockpit build dependencies are unavailable. Run npm ci before building. ${error.message}`);
  }
  rmSync(output, {recursive: true, force: true});
  mkdirSync(output, {recursive: true});
  const options = {
    bundle: true,
    entryPoints: [join(source, "index.jsx")],
    assetNames: "assets/[name]-[hash]",
    legalComments: "external",
    // The cockpit host module is provided by cockpit-ws at runtime.
    external: ["cockpit"],
    loader: {
      ".js": "jsx", ".jsx": "jsx",
      ".woff": "file", ".woff2": "file", ".svg": "file",
      ".png": "file", ".jpg": "file", ".jpeg": "file",
    },
    minify: process.env.NODE_ENV === "production",
    outdir: output,
    sourcemap: process.env.NODE_ENV === "production" ? false : "linked",
    target: ["es2020"],
    plugins: [sassPlugin({loadPaths: [join(root, "node_modules")], quietDeps: true})],
    metafile: true,
  };
  if (mode === "--watch" || mode === "watch") {
    const context = await esbuild.context(options);
    await context.watch();
    copyAssets();
    console.log("Watching cockpit/src and rebuilding cockpit/dist");
    await new Promise(() => {});
  } else {
    const result = await esbuild.build(options);
    copyAssets();
    verifyReferencedAssets();
    integrity.writeBuildMeta({
      outputDir: output,
      schemaVersion: 2,
      sourceSha256: sourceHash(),
      inputs: Object.keys(result.metafile.inputs).sort(),
      outputFiles: outputRecords(),
    });
  }
}

function check() {
  sourceCheck();
  if (!existsSync(join(root, "package-lock.json"))) throw new Error("cockpit/package-lock.json is required for a complete bundle check");
  integrity.checkBundle({
    label: "cockpit",
    sourceSha256: sourceHash(),
    outputDir: output,
    schemaVersion: 2,
    requiredAssets: ["index.html", "manifest.json", "index.js", "index.css", "build-meta.json"],
    exclude: ["README.md"],
    missingHint: "run npm ci && npm run build",
    staleHint: "rebuild the React/PatternFly bundle",
    extraVerify: () => {
      verifyReferencedAssets();
      const html = readFileSync(join(output, "index.html"), "utf8");
      if (!html.includes('src="index.js"') || !html.includes('href="index.css"')) throw new Error("Cockpit distribution entry point is invalid");
    },
  });
}

if (mode === "--check-source" || mode === "check-source") sourceCheck();
else if (mode === "--check" || mode === "check") check();
else await build();
