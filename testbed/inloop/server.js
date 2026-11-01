// Container 2: parameter-triggered infinite loop (CPU-exhaustion logic bomb), Node.js.
// Node is single-threaded for JS execution: a /vulnerable request enters a busy loop and
// never yields, so the event loop is blocked and the connection is held open indefinitely.
// This is the clearest "close() never happens" case the paper targets.
const http = require("http");

const server = http.createServer((req, res) => {
  if (req.url.startsWith("/vulnerable")) {
    // Spin forever (or for a long bounded time if ?ms= is given, to keep the demo recoverable).
    const ms = parseInt(new URL(req.url, "http://x").searchParams.get("ms") || "0", 10);
    const deadline = ms > 0 ? Date.now() + ms : Infinity;
    while (Date.now() < deadline) {
      /* burn CPU */
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "done" }));
  } else {
    // /safe and everything else: respond immediately (benign baseline).
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "ok" }));
  }
});

server.listen(8002, "0.0.0.0", () => console.log("inloop listening on 8002"));
