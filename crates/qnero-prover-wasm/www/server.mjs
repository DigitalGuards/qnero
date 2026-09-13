// A static file server for the harness, with the headers a later threads
// experiment would need already set.
//
// Two reasons it exists rather than a file:// URL. `crypto.getRandomValues` is
// defined only in a secure context, and http://localhost counts as one where a
// file:// origin and a plain http:// LAN address do not; and module and wasm
// fetch semantics do not work from file:// at all.
//
// COOP and COEP are set here even though this measurement is single threaded.
// Turning them on later is a header change on the real wallet's origin, and a
// harness that could not serve them would hide that cost until the experiment
// that needs it. Nothing about them slows a single-threaded run down.

import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".bin": "application/octet-stream",
  ".css": "text/css; charset=utf-8",
};

export function serve(root, port = 0) {
  const base = resolve(root);
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, "http://localhost");
    const requested = url.pathname === "/" ? "/index.html" : url.pathname;
    // Everything below `base`, and nothing above it.
    const path = join(base, normalize(requested).replace(/^(\.\.[/\\])+/, ""));
    if (!path.startsWith(base + sep) && path !== base) {
      response.writeHead(403).end("outside the served directory");
      return;
    }

    let info;
    try {
      info = await stat(path);
    } catch {
      response.writeHead(404).end(`no such file: ${requested}`);
      return;
    }
    if (!info.isFile()) {
      response.writeHead(404).end(`not a file: ${requested}`);
      return;
    }

    response.writeHead(200, {
      "content-type": TYPES[extname(path)] ?? "application/octet-stream",
      "content-length": info.size,
      "cache-control": "no-store",
      // Cross-origin isolation, ready for a threads experiment that does not
      // exist yet. See the module comment.
      "cross-origin-opener-policy": "same-origin",
      "cross-origin-embedder-policy": "require-corp",
      "cross-origin-resource-policy": "same-origin",
    });
    createReadStream(path).pipe(response);
  });

  return new Promise((ok, fail) => {
    server.once("error", fail);
    server.listen(port, "127.0.0.1", () => {
      ok({ server, port: server.address().port });
    });
  });
}

// `node server.mjs [port]` serves the harness for a human with a browser.
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.argv[2] ?? 8787);
  const { port: bound } = await serve(new URL(".", import.meta.url).pathname, port);
  console.log(`serving the harness on http://localhost:${bound}/`);
}
