import {test, expect} from "@playwright/test";
import {build} from "esbuild";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {createAuthentikCspFixture} from "../../tests/lib/authentik-csp-fixture.mjs";

let fixture;
const bundles = {};
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'none'";

test.beforeAll(async () => {
  fixture = await createAuthentikCspFixture();
  for (const original of [true, false]) {
    const result = await build({
      entryPoints: [
        fileURLToPath(new URL("../../tests/browser/authentik-csp-probe.mjs", import.meta.url)),
      ],
      nodePaths: [path.join(fixture.directory, "node_modules")],
      bundle: true,
      format: "esm",
      platform: "browser",
      write: false,
      plugins: original ? [] : [fixture.styleLoaderPlugin()],
    });
    bundles[String(original)] = result.outputFiles[0].text;
  }
});

test.afterAll(async () => {
  await fixture?.dispose();
});

test("pinned Lit styles use CSSOM from first render without allowing hostile attributes", async ({
  page,
}) => {
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  await page.route("**/authentik-csp*", (route) => {
    const url = new URL(route.request().url());
    const original = url.searchParams.get("original");
    return url.pathname.endsWith(".js")
      ? route.fulfill({contentType: "text/javascript", body: bundles[original]})
      : route.fulfill({
          contentType: "text/html",
          headers: {"Content-Security-Policy": csp},
          body: `<!doctype html><html data-original="${original}"><body><script type="module" src="/authentik-csp.js?original=${original}"></script></body></html>`,
        });
  });
  for (const original of [true, false]) {
    await page.goto(`/authentik-csp.html?original=${original}`);
    await page.waitForFunction(() => globalThis.cspResult);
    const result = await page.evaluate(() => globalThis.cspResult);
    expect(result.hostileColor).toBe("rgb(0, 0, 0)");
    expect(result.violations).toEqual(
      original ? ["style-src-attr", "style-src-attr"] : ["style-src-attr"],
    );
    expect(result.attributeWrites).toEqual(original ? ["hostile", "styled"] : ["hostile"]);
    if (original) {
      expect(result.initial.color).toBe("rgb(0, 0, 0)");
      expect(result.initial.custom).toBe("");
    } else {
      expect(result.initial).toEqual({
        color: "rgb(11, 22, 33)",
        width: "41px",
        marginTop: "5px",
        custom: "14px -25px",
        background: "rgb(40, 50, 60)",
        priority: "important",
      });
    }
    expect(result.updated).toEqual({
      color: "rgb(44, 55, 66)",
      width: "42px",
      marginTop: "0px",
      custom: "15px -26px",
      background: "rgba(0, 0, 0, 0)",
      priority: "",
    });
    expect(result.emptyStyle).toBe(true);
    expect(result.removed.color).toBe("rgb(0, 0, 0)");
    expect(result.removed.custom).toBe("");
  }
  expect(pageErrors).toEqual([]);
});
