
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

// Basic per-IP rate limiting.
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
    const parsed = ipaddr.process(address);
    return parsed.range() === "unicast";
  } catch {
    return false;
  }
}

// Pin connections to DNS results that have passed validation.
function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, {
    all: true,
    verbatim: true
  }, (error, addresses) => {
    if (error) return callback(error);

    if (!addresses.length ||
        addresses.some(item => !isPublicAddress(item.address))) {
      return callback(new Error("Destination address is not permitted"));
    }

    const selected = addresses[0];

    if (options && options.all) {
      return callback(null, addresses);
    }

    callback(null, selected.address, selected.family);
  });
}

function validateURL(input) {
  let url;

  try {
    url = new URL(input);
  } catch {
    throw new Error("Invalid website address");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS websites are supported");
  }

  if (url.username || url.password) {
    throw new Error("Credentials in URLs are not supported");
  }

  if (url.port && !["80", "443"].includes(url.port)) {
    throw new Error("This destination port is not supported");
  }

  const hostname = url.hostname.toLowerCase();

  if (
    !hostname ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    throw new Error("This destination is not permitted");
  }

  if (net.isIP(hostname)) {
    if (!isPublicAddress(hostname)) {
      throw new Error("Private network addresses are not permitted");
    }
  }

  return url;
}

function proxyURL(target) {
  return "https://nexplayproxy.onrender.com/api/proxy?url=" +
    encodeURIComponent(target);
}

function rewriteCSS(css, baseURL) {
  // Rewrite CSS url(...) references.
  css = css.replace(
    /url\(\s*(['"]?)(.*?)\1\s*\)/gi,
    (match, quote, value) => {
      value = value.trim();

      if (!value ||
          /^(data:|blob:|javascript:|#)/i.test(value)) {
        return match;
      }

      try {
        const absolute = new URL(value, baseURL).href;
        return `url("${proxyURL(absolute)}")`;
      } catch {
        return match;
      }
    }
  );

  // Rewrite quoted CSS @import references.
  css = css.replace(
    /@import\s+(?!url\()(['"])(.*?)\1/gi,
    (match, quote, value) => {
      try {
        const absolute = new URL(value, baseURL).href;
        return `@import "${proxyURL(absolute)}"`;
      } catch {
        return match;
      }
    }
  );

  return css;
}

function rewriteHTML(html, baseURL) {
  const $ = cheerio.load(html);

  // Remove upstream restrictions that would prevent the page
  // from rendering inside Nexplay. This does not bypass website
  // authentication or access controls.
  $('meta[http-equiv="Content-Security-Policy"]').remove();

  // Preserve the original base for relative URLs used by scripts.
  $("head").prepend(`<base href="${baseURL.replace(/"/g, "&quot;")}">`);

  $("a[href], link[href], script[src], img[src], iframe[src], source[src], video[src], audio[src], form[action], input[src], object[data]").each((_, element) => {
    const attributes = ["href", "src", "action", "data"];

    for (const attribute of attributes) {
      const value = $(element).attr(attribute);
      if (!value) continue;

      if (/^(data:|blob:|javascript:|mailto:|tel:|#)/i.test(value)) {
        continue;
      }

      try {
        const absolute = new URL(value, baseURL).href;
        $(element).attr(attribute, proxyURL(absolute));
      } catch {
        // Leave unsupported attributes unchanged.
      }
    }
  });

  // Rewrite inline styles.
  $("[style]").each((_, element) => {
    const style = $(element).attr("style");
    $(element).attr("style", rewriteCSS(style, baseURL));
  });

  // Rewrite stylesheets embedded in HTML.
  $("style").each((_, element) => {
    const css = $(element).html() || "";
    $(element).html(rewriteCSS(css, baseURL));
  });

  return $.html();
}

async function fetchWebsite(initialURL) {
  let target = validateURL(initialURL);

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    target = validateURL(target.href);

    const agent = new Agent({
      connect: {
        lookup: safeLookup
      },
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
          throw new Error("Too many website redirects");
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
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end("Nexplay Proxy: " + message);
}

const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || "unknown";

  if (!rateAllowed(ip)) {
    return sendError(res, 429, "Too many requests. Please wait.");
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    return sendError(res, 405, "Only GET and HEAD are supported.");
  }

  let pathname;

  try {
    pathname = new URL(req.url, "http://localhost").pathname;
  } catch {
    return sendError(res, 400, "Invalid request.");
  }

  if (pathname === "/api/health") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
      "Access-Control-Allow-Origin": "*",
    });

    return res.end(JSON.stringify({
      ok: true,
      app: "Nexplay Proxy",
      engine: "Nexplay Custom Engine",
      status: "online"
    }));
  }

  if (pathname === "/api/proxy") {
    let target;

    try {
      const params = new URL(req.url, "http://localhost").searchParams;
      target = params.get("url");

      if (!target) {
        return sendError(res, 400, "Missing website URL.");
      }

      validateURL(target);

      const result = await fetchWebsite(target);
      const contentType = String(result.headers["content-type"] || "application/octet-stream");

      if (
        !contentType.includes("text/html") &&
        !contentType.includes("text/css") &&
        !contentType.startsWith("image/") &&
        !contentType.includes("javascript") &&
        !contentType.includes("json") &&
        !contentType.includes("svg")
      ) {
        return sendError(res, 415, "This content type is not supported.");
      }

      let body = result.body;

      if (contentType.includes("text/html")) {
        body = Buffer.from(
          rewriteHTML(body.toString("utf8"), result.url),
          "utf8"
        );
      } else if (contentType.includes("text/css")) {
        body = Buffer.from(
          rewriteCSS(body.toString("utf8"), result.url),
          "utf8"
        );
      }

      res.writeHead(result.status, {
        "Content-Type": contentType,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin"
      });

      return res.end(req.method === "HEAD" ? undefined : body);
    } catch (error) {
      console.error("Proxy error:", error.message);
      return sendError(res, 502, error.message || "Website could not be loaded.");
    }
  }

  // Serve the local Nexplay browser files.
  let requested = pathname === "/" ? "/index.html" : pathname;
  let filePath = path.resolve(ROOT, "." + requested);

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

    const extension = path.extname(filePath).toLowerCase();

    res.writeHead(200, {
      "Content-Type": MIME[extension] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-cache"
    });

    res.end(req.method === "HEAD" ? undefined : data);
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Nexplay Custom Proxy Engine listening on ${PORT}`);
});
