"use strict";

/**
 * Shared source-bound build-integrity primitives for the Cockpit and
 * first-run-wizard esbuild frontends.
 *
 * This module is the single authority for source hashing, output records,
 * build metadata, and read-only bundle verification. Both build.js entry
 * points must consume it instead of carrying their own digest logic.
 * Verification here is strictly read-only: it never writes, rebuilds, or
 * repairs output.
 */

const { createHash } = require("node:crypto");
const { existsSync, readFileSync, statSync, writeFileSync } = require("node:fs");
const { join, relative } = require("node:path");
const { readdirSync } = require("node:fs");

function listFiles(directory) {
  const result = [];
  if (!existsSync(directory)) return result;
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) result.push(...listFiles(path));
    else result.push(path);
  }
  return result.sort();
}

function sourceHash(root, inputs) {
  const hash = createHash("sha256");
  for (const path of [...inputs].sort()) {
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

function outputRecords(outputDir, exclude = []) {
  const skipped = new Set(["build-meta.json", ...exclude]);
  const records = {};
  for (const path of listFiles(outputDir)) {
    const name = relative(outputDir, path).replaceAll("\\", "/");
    if (skipped.has(name)) continue;
    records[name] = { bytes: statSync(path).size, sha256: fileDigest(path) };
  }
  return records;
}

function writeBuildMeta({ outputDir, schemaVersion, sourceSha256, inputs, outputFiles }) {
  writeFileSync(
    join(outputDir, "build-meta.json"),
    JSON.stringify({ schemaVersion, sourceSha256, inputs, outputFiles }, null, 2) + "\n",
  );
}

function readBuildMeta(outputDir) {
  return JSON.parse(readFileSync(join(outputDir, "build-meta.json"), "utf8"));
}

function checkBundle({
  label,
  sourceSha256,
  outputDir,
  schemaVersion,
  requiredAssets,
  exclude = [],
  missingHint,
  staleHint,
  extraVerify,
}) {
  for (const name of requiredAssets) {
    const path = join(outputDir, name);
    if (!existsSync(path) || statSync(path).size === 0) {
      throw new Error(`${label}/dist/${name} is missing or empty; ${missingHint}`);
    }
  }
  const metadata = readBuildMeta(outputDir);
  if (metadata.schemaVersion !== schemaVersion || metadata.sourceSha256 !== sourceSha256) {
    throw new Error(`${label}/dist is stale or has unsupported build metadata; ${staleHint}`);
  }
  const current = outputRecords(outputDir, exclude);
  if (JSON.stringify(current) !== JSON.stringify(metadata.outputFiles)) {
    throw new Error(`${label}/dist output bytes do not match the reviewed build metadata`);
  }
  if (extraVerify) extraVerify(outputDir, metadata);
}

module.exports = {
  listFiles,
  sourceHash,
  fileDigest,
  outputRecords,
  writeBuildMeta,
  readBuildMeta,
  checkBundle,
};
