
const http = require("http");
const fs = require("fs");
const path = require("path");
const dns = require("dns");
const net = require("net");
const cheerio = require("cheerio");
const ipaddr = require("ipaddr.js");
const { Agent, request } = require("undici");

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const BACKEND_URL = "https://nexplayproxy.onrender.com";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon"
};

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400"
};

const requests = new Map();

function rateAllowed(ip) {
  const now = Date.now();
  let entry = requests.get(ip);

  if (!entry || now - entry.start > 60000) {
    entry = { start: now, count: 0 };
  }

  entry.count++;
  requests.set(ip, entry);

  return entry.count <= 60;
}

function isPublicAddress(address) {
  try {
    return ipaddr.process(address).range() === "unicast";
  } catch {
    return false;
  }
}

function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, {
    all: true,
    verbatim: true
  }, (error, addresses) => {
    if (error) return callback(error);

    if (
      !addresses.length ||
      addresses.some(item => !isPublicAddress(item.address))
    ) {
      return callback(new Error("Destination address is not permitted"));
    }

    if (options && options.all) {
      return callback(null, addresses);
    }

    callback(null, addresses[0].address, addresses[0].family);
  });
}

function validateURL(input) {
  const url = new URL(input);

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS websites are supported");
  }

  if (url.username || url.password) {
    throw new Error("URL credentials are not supported");
  }

  if (url.port && !["80", "443"].includes(url.port)) {
    throw new Error("Destination port not supported");
  }

  const hostname = url.hostname.toLowerCase();

  if (
    !hostname ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    throw new Error("Destination not permitted");
  }

  if (net.isIP(hostname) && !isPublicAddress(hostname)) {
    throw new Error("Private network addresses are not permitted");
  }

  return url;
}

function proxyURL(target) {
  return BACKEND_URL + "/api/proxy?url=" +
    encodeURIComponent(target);
}

function rewriteCSS(css, baseURL) {
  css = css.replace(
    /url\(\s*(['"]?)(.*?)\1\s*\)/gi,
    (match, quote, value) => {
      value = value.trim();

      if (!value || /^(data:|blob:|javascript:|#)/i.test(value)) {
        return match;
      }

      try {
        return `url("${proxyURL(new URL(value, baseURL).href)}")`;
      } catch {
        return match;
      }
    }
  );

  return css.replace(
    /@import\s+(?!url\()(['"])(.*?)\1/gi,
    (match, quote, value) => {
      try {
        return `@import "${proxyURL(new URL(value, baseURL).href)}"`;
      } catch {
        return match;
      }
    }
  );
}

function rewriteHTML(html, baseURL) {
  const $ = cheerio.load(html);

  $('meta[http-equiv="Content-Security-Policy"]').remove();
  $("base").remove();

  $("a[href], link[href], script[src], img[src], iframe[src], source[src], video[src], audio[src], form[action], input[src], object[data]").each((_, element) => {
    for (const attribute of ["href", "src", "action", "data"]) {
      const value = $(element).attr(attribute);

      if (!value || /^(data:|blob:|javascript:|mailto:|tel:|#)/i.test(value)) {
        continue;
      }

      try {
        const absolute = new URL(value, baseURL).href;
        $(element).attr(attribute, proxyURL(absolute));
      } catch {}
    }
  });

  $("[style]").each((_, element) => {
    const style = $(element).attr("style");
    $(element).attr("style", rewriteCSS(style, baseURL));
  });

  $("style").each((_, element) => {
    $(element).html(
      rewriteCSS($(element).html() || "", baseURL)
    );
  });

  return $.html();
}

async function fetchWebsite(initialURL) {
  let target = validateURL(initialURL);

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    target = validateURL(target.href);

    const agent = new Agent({
      connect: { lookup: safeLookup },
      headersTimeout: 15000,
      bodyTimeout: 20000
    });

    try {
      const response = await request(target, {
        dispatcher: agent,
        method: "GET",
        maxRedirections: 0,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; NexplayProxy/1.0)",
          "Accept": "text/html,text/css,image/avif,image/webp,image/*,*/*;q=0.8"
        }
      });

      const status = response.statusCode;
      const location = response.headers.location;

      if ([301, 302, 303, 307, 308].includes(status) && location) {
        response.body.destroy();

        if (redirects === MAX_REDIRECTS) {
          throw new Error("Too many redirects");
        }

        target = new URL(location, target);
        continue;
      }

      if (status >= 400) {
        response.body.destroy();
        throw new Error(`Website returned HTTP ${status}`);
      }

      const chunks = [];
      let total = 0;

      for await (const chunk of response.body) {
        total += chunk.length;

        if (total > MAX_BYTES) {
          response.body.destroy();
          throw new Error("Website response is too large");
        }

        chunks.push(chunk);
      }

      return {
        status,
        headers: response.headers,
        body: Buffer.concat(chunks),
        url: target.href
      };
    } finally {
      await agent.close().catch(() => {});
    }
  }

  throw new Error("Unable to retrieve website");
}

function sendError(res, status, message) {
  res.writeHead(status, {
    ...CORS,
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });

  res.end("Nexplay Proxy: " + message);
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    return res.end();
  }

  if (!["GET", "HEAD"].includes(req.method)) {
    return sendError(res, 405, "Only GET and HEAD are supported.");
  }

  let pathname;

  try {
    pathname = new URL(req.url, "http://localhost").pathname;
  } catch {
    return sendError(res, 400, "Invalid request.");
  }

  // Health check runs before rate limiting.
  if (pathname === "/api/health") {
    console.log("Nexplay health check received");

    res.writeHead(200, {
      ...CORS,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    });

    return res.end(JSON.stringify({
      ok: true,
      app: "Nexplay Proxy",
      engine: "Nexplay Custom Engine",
      status: "online"
    }));
  }

  const ip = req.socket.remoteAddress || "unknown";

  if (!rateAllowed(ip)) {
    return sendError(res, 429, "Too many requests. Please wait.");
  }

  if (pathname === "/api/proxy") {
    try {
      const params = new URL(req.url, "http://localhost").searchParams;
      const target = params.get("url");

      if (!target) {
        return sendError(res, 400, "Missing website URL.");
      }

      validateURL(target);

      console.log("Proxy request:", target);

      const result = await fetchWebsite(target);
      const contentType = String(
        result.headers["content-type"] || "application/octet-stream"
      );

      if (
        !contentType.includes("text/html") &&
        !contentType.includes("text/css") &&
        !contentType.startsWith("image/") &&
        !contentType.includes("javascript") &&
        !contentType.includes("json") &&
        !contentType.includes("svg")
      ) {
        return sendError(res, 415, "Content type not supported.");
      }

      let body = result.body;

      if (contentType.includes("text/html")) {
        body = Buffer.from(
          rewriteHTML(body.toString("utf8"), result.url)
        );
      } else if (contentType.includes("text/css")) {
        body = Buffer.from(
          rewriteCSS(body.toString("utf8"), result.url)
        );
      }

      res.writeHead(result.status, {
        ...CORS,
        "Content-Type": contentType,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"
      });

      return res.end(req.method === "HEAD" ? undefined : body);
    } catch (error) {
      console.error("Proxy error:", error.message);
      return sendError(res, 502, error.message);
    }
  }

  const requested = pathname === "/" ? "/index.html" : pathname;
  const filePath = path.resolve(ROOT, "." + requested);

  if (
    filePath !== path.join(ROOT, "index.html") &&
    !filePath.startsWith(ROOT + path.sep)
  ) {
    return sendError(res, 403, "Forbidden.");
  }

  fs.readFile(filePath, (error, data) => {
    if (error) {
      return sendError(res, 404, "File not found.");
    }

    res.writeHead(200, {
      ...CORS,
      "Content-Type":
        MIME[path.extname(filePath).toLowerCase()] ||
        "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-cache"
    });

    res.end(req.method === "HEAD" ? undefined : data);
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Nexplay Custom Proxy Engine listening on ${PORT}`);
});
