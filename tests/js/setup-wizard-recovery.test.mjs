import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {createRequire} from "node:module";
import {fileURLToPath} from "node:url";

const wizardRoot = fileURLToPath(new URL("../../setup/first-run-wizard/", import.meta.url));
const wizardRequire = createRequire(path.join(wizardRoot, "package.json"));
const esbuildPath = wizardRequire.resolve("esbuild");
const {build} = (await import(esbuildPath)).default ?? (await import(esbuildPath));

// Renders the shipped wizard components (not copies) for each case.
async function render(cases) {
  const src = path.join(wizardRoot, "src");
  const entry = `
    import React from "react";
    import {renderToString} from "react-dom/server";
    import {Wizard, WizardStep} from "@patternfly/react-core";
    import SetupNotice from ${JSON.stringify(path.join(src, "SetupNotice.jsx"))};
    import ConfirmStep from ${JSON.stringify(path.join(src, "steps/ConfirmStep.jsx"))};
    import * as state from ${JSON.stringify(path.join(src, "setup-state.js"))};
    const confirm = (props) => (
      <Wizard>
        <WizardStep id="wizard-confirm" name="Confirm">
          <ConfirmStep onRefreshPlan={() => {}} {...props} />
        </WizardStep>
      </Wizard>
    );
    globalThis.__NAS_WIZARD__ = {
      state,
      html: globalThis.__CASES__.map(([kind, props]) =>
        renderToString(kind === "notice" ? <SetupNotice onRefresh={() => {}} {...props} /> : confirm(props)),
      ),
    };
  `;
  const result = await build({
    stdin: {contents: entry, loader: "jsx", resolveDir: src},
    jsx: "automatic",
    jsxImportSource: "react",
    bundle: true,
    format: "cjs",
    platform: "node",
    write: false,
    logLevel: "silent",
    loader: {".css": "empty"},
    define: {"process.env.NODE_ENV": '"production"'},
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nas-wizard-recovery-"));
  const file = path.join(dir, "bundle.cjs");
  fs.writeFileSync(file, result.outputFiles[0].text);
  const originalError = console.error;
  console.error = () => {};
  globalThis.__CASES__ = cases;
  try {
    wizardRequire(file);
    return globalThis.__NAS_WIZARD__;
  } finally {
    console.error = originalError;
    delete globalThis.__CASES__;
    delete globalThis.__NAS_WIZARD__;
    fs.rmSync(dir, {recursive: true, force: true});
  }
}

const ADMINISTRATOR = {
  username: "nasadmin",
  name: "NAS Administrator",
  email: "admin@example.test",
  password: "administrator-password",
  confirm: "administrator-password",
};
const BLOCKED = {
  status: "manual-recovery-required",
  setupJournal: {status: "manual-recovery-required", step: "identity-database-regeneration"},
  message: "Setup stopped at identity-database-regeneration and needs manual recovery. Use nas-setup reconcile-first-run.",
};
const READY = {status: "ready", planDigest: "a".repeat(64), storage: {devices: []}, setupJournal: null};
const confirmProps = (plan) => ({
  administrator: ADMINISTRATOR,
  keePassPassword: "database-password",
  keePassPasswordConfirm: "database-password",
  allowDestructive: false,
  encryptStorage: true,
  plan,
});
const runSetupButton = (html) => html.match(/<button[^>]*>(?:(?!<\/button>).)*Run setup(?:(?!<\/button>).)*<\/button>/s)?.[0];

test("manual recovery is shown before any password is submitted, without acknowledging it", async () => {
  const {html} = await render([["notice", {plan: BLOCKED}]]);
  const [notice] = html;
  assert.match(notice, /id="wizard-recovery-required"/);
  assert.match(notice, /Setup needs manual recovery/);
  assert.match(notice, /identity-database-regeneration/);
  assert.match(notice, /href="\/console\/nas#\/setup"/);
  assert.doesNotMatch(notice, /<form|<input|<textarea/, "the wizard never collects a recovery acknowledgement");
});

test("confirmation cannot start setup while the CLI reports manual recovery", async () => {
  const {html} = await render([
    ["confirm", confirmProps(BLOCKED)],
    ["confirm", confirmProps(READY)],
  ]);
  const [blocked, ready] = html;
  assert.match(blocked, /Setup cannot start until the recovery shown above is acknowledged/);
  assert.match(runSetupButton(blocked), /disabled=""/);
  assert.ok(runSetupButton(ready), "ready plan renders the submission button");
  assert.doesNotMatch(runSetupButton(ready), /disabled=""/);
});

test("interrupted but resumable journals are explained; clean plans render nothing", async () => {
  const resumable = {...READY, setupJournal: {status: "failed", step: "identity-accounts"}};
  const {html} = await render([
    ["notice", {plan: resumable}],
    ["notice", {plan: READY}],
    ["notice", {plan: {...READY, setupJournal: {status: "running", step: "storage"}}}],
    ["notice", {plan: {status: "journal-invalid", message: "Invalid operation journal"}}],
  ]);
  assert.match(html[0], /id="wizard-setup-resume"/);
  assert.match(html[0], /stopped at identity-accounts/);
  assert.match(html[0], /same administrator and KeePassXC passwords/);
  assert.equal(html[1], "");
  assert.equal(html[2], "", "an active worker's journal is reported by resume, not as interrupted");
  assert.match(html[3], /Setup journal needs repair/);
});

test("failed job documents gate retry on their recovery requirement", async () => {
  const {state} = await render([]);
  const blocked = {status: "failed", manualRecovery: {required: true, message: "stopped at storage"}};
  assert.equal(state.jobRecoveryMessage(blocked), "stopped at storage");
  assert.equal(state.jobRecoveryMessage({status: "failed", error: "transient"}), "");
  assert.equal(state.jobRecoveryMessage({...blocked, status: "running"}), "");
  assert.equal(state.planProblem(READY), "");
  assert.equal(state.planProblem({...READY, status: "complete"}), "");
  assert.match(state.planProblem({status: "state-drift", message: "drift"}), /drift/);
  assert.match(state.planProblem(null), /not loaded/);
  assert.match(state.planProblem({...READY, planDigest: "not-a-digest"}), /not loaded/);
});
