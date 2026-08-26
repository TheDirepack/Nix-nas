// SPDX-License-Identifier: LGPL-2.1-or-later
// Vendored from Cockpit pkg/lib/cockpit-dark-theme.ts (upstream main, 2026-08).
// The Cockpit shell publishes its style choice via shared localStorage
// (`shell:style`) and a `cockpit-style` window event into every iframe;
// this module mirrors that choice onto PatternFly's pf-v6-theme-dark class.

function setDarkMode(style) {
  const preference = style || localStorage.getItem("shell:style") || "auto";
  const dark =
    preference === "dark" ||
    (preference === "auto" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("pf-v6-theme-dark", dark);
}

window.addEventListener("storage", (event) => {
  if (event.key === "shell:style") setDarkMode();
});

window.addEventListener("cockpit-style", (event) => {
  if (event instanceof CustomEvent) setDarkMode(event.detail.style);
});

window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => setDarkMode());

setDarkMode();
