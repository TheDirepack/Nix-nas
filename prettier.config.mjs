import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {spawnSync} from "node:child_process";

const options = {
  bracketSpacing: false,
  printWidth: 100,
  proseWrap: "preserve",
  semi: true,
  singleQuote: false,
  trailingComma: "all",
};

// Temporary CI diagnostic: use the exact pinned Prettier executable to print
// canonical copies of the two files still rejected by the formatting gate.
if (process.env.GITHUB_ACTIONS === "true" && !process.env.PRETTIER_DIAGNOSTIC_CHILD) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nas-prettier-diagnostic-"));
  const config = path.join(directory, "prettier.json");
  fs.writeFileSync(config, JSON.stringify(options));

  for (const source of [
    "cockpit/e2e/first-run-wizard.spec.mjs",
    "tests/js/setup-wizard.test.mjs",
  ]) {
    const copy = path.join(directory, path.basename(source));
    fs.copyFileSync(source, copy);
    const result = spawnSync(process.argv[1], ["--config", config, "--write", copy], {
      encoding: "utf8",
      env: {...process.env, PRETTIER_DIAGNOSTIC_CHILD: "1"},
    });
    if (result.status !== 0) {
      console.error(`PRETTIER_DIAGNOSTIC_FAILED ${source}`);
      console.error(result.stderr || result.stdout);
      continue;
    }
    console.error(`PRETTIER_CANONICAL_BEGIN ${source}`);
    console.error(fs.readFileSync(copy, "utf8"));
    console.error(`PRETTIER_CANONICAL_END ${source}`);
  }
}

export default options;
