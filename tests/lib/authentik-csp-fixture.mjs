import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtemp, mkdir, readFile, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixtures = path.join(root, "tests/fixtures/authentik-csp");

export async function createAuthentikCspFixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "nas-authentik-csp-"));
  const dispose = () => rm(directory, {recursive: true, force: true});
  try {
    const manifest = JSON.parse(await readFile(path.join(fixtures, "lit-html.json"), "utf8"));
    const lit = path.join(directory, "node_modules/lit-html");
    for (const [name, digest] of Object.entries(manifest.files)) {
      const content = await readFile(path.join(fixtures, "lit-html", `${name}.txt`));
      assert.equal(createHash("sha256").update(content).digest("hex"), digest, name);
      await mkdir(path.dirname(path.join(lit, name)), {recursive: true});
      await writeFile(path.join(lit, name), content);
    }
    const loader = path.join(directory, "web/bundler/style-loader-plugin/node.js");
    await mkdir(path.dirname(loader), {recursive: true});
    await writeFile(
      loader,
      await readFile(path.join(fixtures, "web/bundler/style-loader-plugin/node.js.txt")),
    );
    execFileSync(
      "git",
      [
        "apply",
        "--include=web/bundler/style-loader-plugin/node.js",
        path.join(root, "authentik/patches/authentik-csp.patch"),
      ],
      {cwd: directory},
    );

    // Only logging and package-location context are stubbed; the production
    // plugin, Lit directive and DOM renderer run without source substitutions.
    await writeFile(
      path.join(directory, "package.json"),
      JSON.stringify({
        type: "module",
        imports: {"#logger/node": "./context.mjs"},
      }),
    );
    await writeFile(
      path.join(directory, "context.mjs"),
      "export const ConsoleLogger = {child: () => ({})};\n",
    );
    const core = path.join(directory, "node_modules/@goauthentik/core");
    await mkdir(core, {recursive: true});
    await writeFile(
      path.join(core, "package.json"),
      JSON.stringify({
        type: "module",
        exports: {"./paths/node": "./paths.mjs"},
      }),
    );
    await writeFile(
      path.join(core, "paths.mjs"),
      'export const resolvePackage = () => "/owned-patternfly-fixture";\n',
    );
    const {styleLoaderPlugin} = await import(pathToFileURL(loader).href);
    return {directory, lit, styleLoaderPlugin, dispose};
  } catch (error) {
    await dispose();
    throw error;
  }
}
