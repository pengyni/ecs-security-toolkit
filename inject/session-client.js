(function () {
  if (typeof window === "undefined" || window.__ecsLoginAckInstalled) return;
  window.__ecsLoginAckInstalled = 1;

  function usernameFromBody(b) {
    if (!b) return "";
    if (typeof URLSearchParams !== "undefined" && b instanceof URLSearchParams) {
      return String(b.get("username") || b.get("user") || b.get("login") || b.get("cvalue") || "").slice(0, 32);
    }
    if (typeof b === "string") {
      try {
        var j = JSON.parse(b);
        return String(j.username || j.user || j.login || j.cvalue || "").slice(0, 32);
      } catch (_) {
        var u = /(?:username|user|login|cvalue)=([^&]+)/i.exec(b);
        return u ? decodeURIComponent(u[1]).slice(0, 32) : "";
      }
    }
    if (typeof FormData !== "undefined" && b instanceof FormData) {
      return String(b.get("username") || b.get("user") || b.get("login") || b.get("cvalue") || "").slice(0, 32);
    }
    if (typeof b === "object") {
      return String(b.username || b.user || b.login || b.cvalue || "").slice(0, 32);
    }
    return "";
  }

  function isLoginUrl(u) {
    return /\/login(?:\?|$)|signin|sign-in|auth\/v2\/login|authenticate/i.test(String(u || ""));
  }

  function ackUsername(u) {
    if (!u) return;
    try {
      fetch("__SESSION_ACK__", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: u, ok: true }),
      }).catch(function () {});
    } catch (_) {}
  }

  var f = window.fetch;
  if (f) {
    window.fetch = function (i, n) {
      var u = typeof i === "string" ? i : i && i.url;
      var m = ((n && n.method) || (i && i.method) || "GET").toUpperCase();
      var name = m === "POST" && isLoginUrl(u) ? usernameFromBody(n && n.body) : "";
      return f.apply(this, arguments).then(function (r) {
        if (name && r && r.ok) ackUsername(name);
        return r;
      });
    };
  }
})();
