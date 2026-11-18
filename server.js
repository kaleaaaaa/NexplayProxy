
const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon"
};

const server = http.createServer((req, res) => {
  if (req.url === "/api/health") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    });
    return res.end(JSON.stringify({
      ok: true,
      app: "Nexplay Proxy",
      status: "online"
    }));
  }

  let pathname;

  try {
    pathname = decodeURIComponent(
      (req.url || "/").split("?")[0]
    );
  } catch {
    res.writeHead(400);
    return res.end("Bad request");
  }

  const requested = pathname === "/" ? "/index.html" : pathname;
  const filePath = path.resolve(ROOT, "." + requested);

  if (
    filePath !== path.join(ROOT, "index.html") &&
    !filePath.startsWith(ROOT + path.sep)
  ) {
    res.writeHead(403);
    return res.end("Forbidden");
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, {
        "Content-Type": "text/plain; charset=utf-8"
      });
      return res.end("Not found");
    }

    res.writeHead(200, {
      "Content-Type":
        MIME[path.extname(filePath).toLowerCase()] ||
        "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Cache-Control": "no-cache"
    });

    res.end(data);
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Nexplay Proxy listening on ${PORT}`);
});
