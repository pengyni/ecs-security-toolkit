"""Aggressive mechanical hardening: auto-fix instead of flag-for-review where possible."""
from __future__ import annotations

import re
import shutil
from pathlib import Path

EXPRESS_GUARD = """
// asp-security-guard
app.use((req,res,next)=>{
  const p=String(req.path||'');
  if(/^\\/(?:__debug|debug|internal|_status|phpinfo|server-status)(?:\\/|$)/i.test(p)) return res.status(404).end();
  const red=req.query&& (req.query.redirect||req.query.next||req.query.url||req.query.return);
  if(typeof red==='string'&& /^https?:\\/\\//i.test(red)) return res.status(400).json({error:'redirect blocked'});
  next();
});
"""


def harden_comprehensive(path: Path, text: str, report) -> str:
    suffix = path.suffix.lower()
    if suffix not in {".js", ".jsx", ".ts", ".tsx", ".html", ".cs", ".json"}:
        return text

    lower = path.name.lower()

    # ── RCE / code execution sinks ──
    rce_patterns = [
        (r"\beval\s*\(\s*((?:req|request)\.[^)]+)\)", r"void(\1)"),
        (r"\bnew\s+Function\s*\(\s*[^)]*(?:req|request)\.", "void(null); /* blocked */"),
        (r"\bvm\.(?:runInThisContext|runInNewContext|createScript)\s*\(\s*(?:req|request)\.", "void(null); /* blocked */"),
        (r"child_process\.(?:exec|execSync|spawn)\s*\(\s*(?:req|request)\.", "void(null); /* blocked */"),
    ]
    for pat, repl in rce_patterns:
        new_text, n = re.subn(pat, repl, text)
        if n:
            text = new_text
            report.fixed("rce-sink-neutralized", path)

    # ── Path traversal / arbitrary file read ──
    if re.search(r"fs\.(?:readFile|readFileSync|createReadStream)\s*\(", text):
        new_text, n = re.subn(
            r"fs\.(readFileSync|readFile|createReadStream)\s*\(\s*([^)]+)\)",
            lambda m: (
                f"fs.{m.group(1)}(String({m.group(2).strip()}).replace(/\\.\\./g,'').replace(/^\\/+/, ''))"
                if re.search(r"(req|request|query|params|body)", m.group(2))
                else m.group(0)
            ),
            text,
        )
        if n:
            text = new_text
            report.fixed("path-traversal-fs", path)

    # ── XSS: dangerouslySetInnerHTML ──
    def _sanitize_dhtml(m: re.Match) -> str:
        inner = m.group(2)
        if re.search(r"(req\.|request\.|props\.|query|params|body|user)", inner):
            report.fixed("xss-dangerouslySetInnerHTML-sanitized", path)
            return f"{m.group(1)}String({inner.strip()}).replace(/[<>&\"']/g,''){m.group(3)}"
        return m.group(0)

    text = re.sub(
        r"(__html\s*:\s*)([^}]+)(\}\s*\})",
        _sanitize_dhtml,
        text,
    )

    if re.search(r"document\.write\s*\(\s*(?:req|request)\.", text):
        text = re.sub(r"document\.write\s*\([^)]+\)\s*;?", "", text)
        report.fixed("xss-document-write-removed", path)

    # ── Debug / backdoor routes ──
    debug_route = re.compile(
        r"app\.(get|post|all|use)\s*\(\s*['\"](?:__debug|debug|internal|_status|phpinfo)['\"][^;]*;?",
        re.I,
    )
    new_text, n = debug_route.subn(
        "app.$1('/__blocked_debug', (_req,res)=>res.status(404).end());",
        text,
    )
    if n:
        text = new_text
        report.fixed("debug-endpoint-disabled", path)

    # ── Hard-coded secrets (48+ chars) ──
    secret_re = re.compile(r"(['\"])([A-Za-z0-9_\-]{48,})\1")
    if secret_re.search(text):
        text = secret_re.sub(r"\1USE_ENV_VAR_PLACEHOLDER\1", text, count=5)
        report.fixed("hardcoded-secret-redacted", path)

    # ── CSP unsafe-inline ──
    if "unsafe-inline" in text and "Content-Security-Policy" in text:
        text2 = re.sub(r"unsafe-inline\s*;?", "", text)
        if text2 != text:
            text = text2
            report.fixed("csp-unsafe-inline-removed", path)

    # ── TLS verify ──
    if re.search(r"rejectUnauthorized\s*:\s*false", text, re.I):
        text = re.sub(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", text, flags=re.I)
        report.fixed("tls-verify-enabled", path)

    # ── NoSQL $where ──
    if "$where" in text:
        text = text.replace("$where", "$blocked_where")
        report.fixed("nosql-where-neutralized", path)

    # ── Prototype pollution keys ──
    if "__proto__" in text:
        text = text.replace("__proto__", "_proto_blocked_")
        report.fixed("prototype-pollution-key-neutralized", path)

    # ── Cookies / sessions (broader file match) ──
    if suffix in {".js", ".ts", ".cs"} and any(k in lower for k in ("cookie", "session", "auth", "express")):
        text = re.sub(r"\bhttpOnly\s*:\s*false\b", "httpOnly: true", text)
        text = re.sub(r"\bsecure\s*:\s*false\b", "secure: true", text, flags=re.I)
        text = re.sub(r'\bsameSite\s*:\s*["\']?none["\']?', "sameSite: 'lax'", text, flags=re.I)

    # ── CORS wildcard ──
    text = re.sub(
        r"(Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"])\*(['\"])",
        r"\1null\2",
        text,
        flags=re.I,
    )

    return text


def inject_express_guard(text: str) -> str:
    if "asp-security-guard" in text:
        return text
    if not re.search(r"\b(?:const|let|var)\s+app\s*=\s*express\s*\(\s*\)", text):
        return text
    return re.sub(
        r"(\b(?:const|let|var)\s+app\s*=\s*express\s*\(\s*\)\s*;?)",
        r"\1" + EXPRESS_GUARD,
        text,
        count=1,
    )


def quarantine_public_env(pub_env: Path, root: Path, report) -> None:
    if not pub_env.is_file():
        return
    dest = root / ".quarantined-env" / pub_env.relative_to(root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(pub_env), str(dest))
    try:
        dest.chmod(0o600)
    except OSError:
        pass
    report.fixed("env-in-public-quarantined", pub_env)
