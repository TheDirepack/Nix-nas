"use strict";

(() => {
  const form = document.getElementById("unlock-form");
  const input = document.getElementById("unlock-password");
  const button = document.getElementById("unlock-submit");
  const status = document.getElementById("unlock-status");

  const show = (message, kind = "") => {
    status.textContent = message;
    status.dataset.kind = kind;
  };

  const finishUnlocked = () => {
    form.hidden = true;
    show("Unlocked. Protected services are starting; you will be asked to sign in again.", "ok");
    window.setTimeout(() => window.location.assign("/"), 5000);
  };

  const readJson = async (response) => {
    if (response.type === "opaqueredirect") return null;
    const type = response.headers.get("Content-Type") || "";
    if (!type.startsWith("application/json")) return null;
    try {
      return await response.json();
    } catch (_error) {
      return null;
    }
  };

  const refresh = async () => {
    try {
      const response = await fetch("/unlock/api/status", {credentials: "same-origin", redirect: "manual"});
      const body = await readJson(response);
      if (!body) return;
      if (body.locked === false) {
        finishUnlocked();
      } else if (body.busy) {
        show("An unlock attempt is already running.");
      } else if (body.retryAfterSeconds > 0) {
        show(`Too many failed attempts; retry in ${body.retryAfterSeconds} seconds.`, "error");
      }
    } catch (_error) {
      // The submit path reports connectivity problems.
    }
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = input.value;
    input.value = "";
    if (!password) return;
    button.disabled = true;
    show("Unlocking. Loading storage keys and starting services can take a few minutes…");
    try {
      const response = await fetch("/unlock/api/activate", {
        method: "POST",
        credentials: "same-origin",
        redirect: "manual",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({password}),
      });
      const body = await readJson(response);
      if (!body) {
        show("Your sign-in expired. Reload the page to sign in again.", "error");
      } else if (response.ok && body.unlocked) {
        finishUnlocked();
        return;
      } else {
        show(body.error || `Unlock failed (HTTP ${response.status}).`, "error");
      }
    } catch (_error) {
      // A completed unlock reloads Caddy, which can drop this response.
      show("The connection was interrupted. Checking the appliance state…");
      window.setTimeout(() => window.location.reload(), 5000);
      return;
    } finally {
      button.disabled = false;
    }
    input.focus();
  });

  refresh();
})();
