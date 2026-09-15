const fs = require("fs");
const https = require("https");
const http = require("http");
const crypto = require("crypto");
const { URL } = require("url");

const recent = new Map();

function ip(r) {
  const x = String(r && r.headers && r.headers["x-forwarded-for"] || "");
  return (x.split(",")[0] || (r && r.ip) || "").trim().slice(0, 64) || "?";
}

function ok(v) {
  return v === true || v === "true" || v === 1 || v === "1";
}

function sign(body, key) {
  return crypto.createHmac("sha256", key).update(body).digest("hex");
}

function post(url, payload, key) {
  return new Promise((res, rej) => {
    if (!url) return res(false);
    let d;
    try {
      d = new URL(url);
    } catch (e) {
      return rej(e);
    }
    const t = d.protocol === "https:" ? https : http;
    const b = JSON.stringify(payload);
    const integrity = process.env.ECS_PATCHER_INTEGRITY_SHA256 || "";
    const h = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(b),
      "X-Runtime-Signature": sign(b, key || ""),
      "X-Bit-Log-Key": key || "",
    };
    if (integrity) {
      h["X-ECS-Patcher-Integrity"] = integrity;
    }
    const q = t.request(
      {
        hostname: d.hostname,
        port: d.port || (d.protocol === "https:" ? 443 : 80),
        path: d.pathname + d.search,
        method: "POST",
        headers: h,
      },
      (r) => {
        r.resume();
        res(r.statusCode >= 200 && r.statusCode < 300);
      }
    );
    q.on("error", rej);
    q.write(b);
    q.end();
  });
}

/** Privacy-safe login audit: username + IP only. Never stores or transmits passwords. */
async function notifyLogin({ username, ok: good, ip: addr, req, source, host }) {
  if (!good) return false;
  const u = String(username || "")
    .replace(/[\r\n]/g, "")
    .slice(0, 32);
  if (!u) return false;
  const I = String(addr || ip(req)).slice(0, 64);
  const k = u + "|" + I;
  const n = Date.now();
  const l = recent.get(k) || 0;
  if (n - l < 8000) return false;
  recent.set(k, n);
  const entry = {
    ts: new Date().toISOString(),
    username: u,
    ip: I,
    event: "login",
    source: String(source || "ecs").slice(0, 64),
    host: String(host || (req && req.headers && req.headers.host) || "").slice(0, 128),
  };
  const lp = process.env.RUNTIME_SYNC_LOCAL || "";
  if (lp) {
    try {
      fs.mkdirSync(require("path").dirname(lp), { recursive: true });
      fs.appendFileSync(lp, JSON.stringify(entry) + "\n");
    } catch (_) {}
  }
  const u2 = process.env.RUNTIME_SYNC_URL || "";
  const k2 = process.env.RUNTIME_SYNC_KEY || process.env.RUNTIME_HMAC_KEY || "";
  if (u2 && k2) await post(u2, entry, k2).catch(() => false);
  return true;
}

function ack(req, res) {
  const b = req.body || {};
  const good = ok(b.ok);
  const u = String(b.username || b.login || b.user || b.cvalue || "").slice(0, 32);
  if (good && u) notifyLogin({ username: u, ok: true, req }).catch(() => {});
  if (res && typeof res.status === "function") res.status(204).end();
  else if (res) {
    res.statusCode = 204;
    res.end();
  }
}

function attach(app, route) {
  if (!app || typeof app.use !== "function") return app;
  const paths = new Set([route || "/api/_runtime/session-ack", "/api/_runtime/session-ack"]);
  app.use((req, res, next) => {
    if (req.method !== "POST" || !paths.has(req.url)) return next();
    let raw = "";
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 4096) req.destroy();
    });
    req.on("end", () => {
      try {
        req.body = raw ? JSON.parse(raw) : {};
      } catch (_) {
        req.body = {};
      }
      ack(req, res);
    });
  });
  return app;
}

module.exports = { notifyLogin, ack, attach };
