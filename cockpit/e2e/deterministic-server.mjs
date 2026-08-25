import {createReadStream, readFileSync, statSync} from "node:fs";
import {createServer} from "node:http";
import {extname, isAbsolute, join, relative, resolve} from "node:path";

const root = resolve(import.meta.dirname, "..", "dist");
const runtimeStub = readFileSync(join(import.meta.dirname, "cockpit-runtime-stub.js"));
const port = Number(process.env.PORT || 4173);
const types = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".woff2": "font/woff2",
};

function assetFor(url) {
  const pathname = decodeURIComponent(new URL(url, "http://127.0.0.1").pathname);
  if (pathname === "/base1/cockpit.js") return {stub: true};
  if (!pathname.startsWith("/")) return null;
  const asset = resolve(root, `.${pathname}`);
  const withinRoot = relative(root, asset);
  if (withinRoot.startsWith("..") || isAbsolute(withinRoot)) return null;
  try {
    return statSync(asset).isFile() ? {asset} : null;
  } catch (_error) {
    return null;
  }
}

const server = createServer((request, response) => {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, {Allow: "GET, HEAD"});
    response.end();
    return;
  }
  let target;
  try {
    target = assetFor(request.url || "/");
  } catch (_error) {
    target = null;
  }
  if (!target) {
    response.writeHead(404);
    response.end();
    return;
  }
  const body = target.stub ? runtimeStub : null;
  response.writeHead(200, {
    "Cache-Control": "no-store",
    "Content-Length": body ? body.length : statSync(target.asset).size,
    "Content-Type": body
      ? "application/javascript; charset=utf-8"
      : types[extname(target.asset)] || "application/octet-stream",
  });
  if (request.method === "HEAD") {
    response.end();
  } else if (body) {
    response.end(body);
  } else {
    createReadStream(target.asset).pipe(response);
  }
});

const shutdown = () => server.close(() => process.exit(0));
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
server.listen(port, "127.0.0.1");
