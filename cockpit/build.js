#!/usr/bin/env node
import {createHash} from "node:crypto";
import {copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync} from "node:fs";
import {join, relative, resolve} from "node:path";
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

function files(directory) {
  const result = [];
  if (!existsSync(directory)) return result;
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) result.push(...files(path));
    else result.push(path);
  }
  return result.sort();
}

function sourceHash() {
  const hash = createHash("sha256");
  const inputs = [...files(source), join(root, "package.json"), join(root, "build.js")];
  const lock = join(root, "package-lock.json");
  if (existsSync(lock)) inputs.push(lock);
  for (const path of inputs.sort()) {
    hash.update(relative(root, path));
    hash.update("\0");
    hash.update(readFileSync(path));
    hash.update("\0");
  }
  return hash.digest("hex");
}

function fileDigest(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function outputRecords() {
  const records = {};
  for (const path of files(output)) {
    const name = relative(output, path).replaceAll("\\", "/");
    if (name === "build-meta.json" || name === "README.md") continue;
    records[name] = {bytes: statSync(path).size, sha256: fileDigest(path)};
  }
  return records;
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
    writeFileSync(join(output, "build-meta.json"), JSON.stringify({
      schemaVersion: 2,
      sourceSha256: sourceHash(),
      inputs: Object.keys(result.metafile.inputs).sort(),
      outputFiles: outputRecords(),
    }, null, 2) + "\n");
  }
}

function check() {
  sourceCheck();
  if (!existsSync(join(root, "package-lock.json"))) throw new Error("cockpit/package-lock.json is required for a complete bundle check");
  for (const name of ["index.html", "manifest.json", "index.js", "index.css", "build-meta.json"]) {
    const path = join(output, name);
    if (!existsSync(path) || statSync(path).size === 0) throw new Error(`cockpit/dist/${name} is missing or empty; run npm ci && npm run build`);
  }
  const metadata = JSON.parse(readFileSync(join(output, "build-meta.json"), "utf8"));
  const expectedSourceSha256 = sourceHash();
  if (metadata.schemaVersion !== 2 || metadata.sourceSha256 !== expectedSourceSha256) {
    throw new Error(`cockpit/dist is stale or has unsupported build metadata; expected source ${expectedSourceSha256}, committed ${metadata.sourceSha256 ?? "missing"}; rebuild the React/PatternFly bundle`);
  }
  const current = outputRecords();
  if (JSON.stringify(current) !== JSON.stringify(metadata.outputFiles)) {
    throw new Error("cockpit/dist output bytes do not match the reviewed build metadata");
  }
  verifyReferencedAssets();
  const html = readFileSync(join(output, "index.html"), "utf8");
  if (!html.includes('src="index.js"') || !html.includes('href="index.css"')) throw new Error("Cockpit distribution entry point is invalid");
}

if (mode === "--check-source" || mode === "check-source") sourceCheck();
else if (mode === "--check" || mode === "check") check();
else await build();
