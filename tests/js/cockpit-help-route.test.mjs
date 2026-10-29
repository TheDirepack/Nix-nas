import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {createRequire} from "node:module";

const require = createRequire(new URL("../../cockpit/package.json", import.meta.url));
const {build} = require("esbuild");
const fixture = await readFile(
  new URL("../fixtures/cockpit-362/manifest-routing.ts.txt", import.meta.url),
  "utf8",
);
const result = await build({
  stdin: {contents: fixture, loader: "ts"},
  bundle: true,
  write: false,
  format: "esm",
  platform: "node",
  plugins: [
    {
      name: "fixture-gettext",
      setup(build) {
        build.onResolve({filter: /^cockpit$/}, () => ({path: "cockpit", namespace: "fixture"}));
        build.onLoad({filter: /.*/, namespace: "fixture"}, () => ({
          contents: "export default {gettext: text => text};",
        }));
      },
    },
  ],
});
const {compile_manifests, compute_frame_url} = await import(
  `data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`
);

for (const cached of [false, true]) {
  test(`NAS Help resolves a packaged manual chapter through the native ${cached ? "cached" : "uncached"} shell`, async () => {
    const nas = JSON.parse(
      await readFile(new URL("../../cockpit/src/manifest.json", import.meta.url), "utf8"),
    );
    const manifests = {nas};
    if (cached) {
      manifests[".checksum"] = "fixture";
      nas[".checksum"] = "fixture";
    }
    const components = compile_manifests(manifests);
    const help = components.ordered("menu").find((item) => item.label === "NAS Help");
    assert.ok(help);
    assert.equal(
      components.find_path_manifest(help.path),
      nas,
      "Help must remain in the installed NAS package",
    );
    const frame = compute_frame_url({connection_string: "localhost", manifests}, help.path);
    const url = new URL(
      frame,
      "https://nas-test.local:8443/console/cockpit/@localhost/shell/index.html",
    );
    const prefix = "/console/cockpit/@localhost/nas/docs/";
    assert.ok(
      url.pathname.startsWith(prefix),
      `Help resolved outside the packaged manual: ${url.pathname}`,
    );
    const chapter = url.pathname.slice(prefix.length).replace(/\.html$/, ".md");
    const summary = await readFile(new URL("../../docs/src/SUMMARY.md", import.meta.url), "utf8");
    assert.ok(
      summary.includes(`](${chapter})`),
      `Help does not select a declared book chapter: ${chapter}`,
    );
    const markdown = await readFile(new URL(`../../docs/src/${chapter}`, import.meta.url), "utf8");
    assert.match(markdown, /^# /);
  });
}
