import {test, expect} from "@playwright/test";
import {spawnSync} from "node:child_process";

const base = "http://127.0.0.1:4173";

function curl(path, ...args) {
  const result = spawnSync(
    "curl",
    [
      "--silent",
      "--show-error",
      "--max-time",
      "10",
      "--output",
      "/dev/null",
      "--write-out",
      "%{http_code}",
      ...args,
      `${base}${path}`,
    ],
    {encoding: "utf8"},
  );
  expect(result.error, result.stderr).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}

test("static Cockpit entry point responds without a browser", () => {
  expect(curl("/index.html")).toBe("200");
});

test("HEAD and query-string requests stay bounded to the static app", () => {
  expect(curl("/index.html?probe=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", "--head")).toBe("200");
});

test("encoded traversal does not escape the static distribution root", () => {
  expect(curl("/%2e%2e/%2e%2e/etc/passwd")).toBe("404");
});

test("hostile nonexistent asset names are not reflected as successful resources", () => {
  for (const path of [
    "/%3Cscript%3Ealert(1)%3C%2Fscript%3E.js",
    "/javascript%3Aalert(1)",
    "/..%2F..%2Fetc%2Fshadow",
  ]) {
    expect(curl(path)).toBe("404");
  }
});
