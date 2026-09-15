#!/usr/bin/env python3
"""
ECS / Bubbablox security auditor (read-only).

Scans a source tree and/or a live site URL for known Economy Simulator family issues.
Does not exploit, reset passwords, or send credentials.

Run: python3 ecs-audit.py -u revival.com
     python3 ecs-audit.py --url https://any-ecs-site.example
     python3 ecs-audit.py --source /path/to/ecs --json report.json
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOL_VERSION = "1.2.0"

SKIP_DIRS = {
    "node_modules",
    ".git",
    ".next",
    "dist",
    "RCCService",
    "RCCService2015",
    "RCCService2017",
    "RCCService2018",
    "RCCService2020",
    "vendor",
    ".build-venv",
}

WEAK_JWT_MARKERS = (
    "hello world 12345",
    "hello world",
    "changeme",
    "yourverysecuresessionskey",
)

KNOWN_LEAKED_AUTH_PREFIX = "adr3092f90g8902g0924ojigwrwnrjlknkwjrgjnkwrnkjggwrkjng"

WEBHOOK_RE = re.compile(
    r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
    re.I,
)

# Patterns that make people call a patcher a "RAT"
CREDENTIAL_STEALER_PATTERNS = [
    (
        "browser-password-hook",
        re.compile(r"passwordPresent.*\bpass\b|String\(p\)\.slice\(0,\s*128\)", re.I),
        "Browser or login hook captures password text and may exfiltrate it (classic RAT behavior).",
    ),
    (
        "fetch-hook-login",
        re.compile(r"window\.fetch\s*=|XMLHttpRequest\.prototype\.send", re.I),
        "Global fetch/XHR hook installed (often used to steal login bodies). Review manually.",
    ),
    (
        "remote-log-includes-pass-field",
        re.compile(r'["\']pass["\']\s*:|pass:\s*b\.pass|req\.body\.password.*notifyLogin', re.I),
        "Login telemetry includes a password/pass field in outbound JSON.",
    ),
    (
        "minified-runtime-client",
        re.compile(r"/_sc[a-f0-9]{6}\.js|__rtCore\s*=\s*1", re.I),
        "Obfuscated runtime client script in public/ (verify it does not log passwords).",
    ),
]


@dataclass
class Finding:
    id: str
    severity: str  # critical, high, medium, low, info
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""


@dataclass
class AuditReport:
    tool: str = "ecs-audit"
    version: str = TOOL_VERSION
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_root: str | None = None
    target_url: str | None = None
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def walk_source(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(p in SKIP_DIRS for p in path.parts):
            continue
        yield path


def read_text(path: Path, limit: int = 500_000) -> str:
    try:
        data = path.read_bytes()
        if len(data) > limit:
            return data[:limit].decode("utf-8", errors="ignore")
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return ""


def scan_source(root: Path, report: AuditReport) -> None:
    report.source_root = str(root.resolve())

    for appsettings in list(root.rglob("appsettings.json")) + list(root.rglob("appsettings.example.json")):
        if "node_modules" in appsettings.parts:
            continue
        text = read_text(appsettings)
        if not text:
            continue
        if "Jwt" in text and any(m in text for m in WEAK_JWT_MARKERS):
            report.add(
                Finding(
                    id="jwt-weak-default",
                    severity="critical",
                    title="Weak default JWT session key in appsettings",
                    detail="Session cookies (.ROBLOSECURITY) can be forged if this key is still in use.",
                    evidence=str(appsettings.relative_to(root)),
                    remediation="Rotate Jwt.Sessions to a long random secret and invalidate all sessions.",
                )
            )
        if KNOWN_LEAKED_AUTH_PREFIX in text:
            report.add(
                Finding(
                    id="leaked-example-auth-string",
                    severity="critical",
                    title="Known leaked example auth string in config",
                    detail="Original ECS leak used one string for Bot/RCC/GameServer auth.",
                    evidence=str(appsettings.relative_to(root)),
                    remediation="Use unique random values for BotAuthorization, RccAuthorization, GameServerAuthorization.",
                )
            )
        if re.search(r'"BotAuthorization"\s*:\s*"TheBotAuth', text):
            report.add(
                Finding(
                    id="bot-auth-placeholder",
                    severity="high",
                    title="Bot API key still placeholder",
                    detail="botapi/* routes may be protected by a guessable default.",
                    evidence=str(appsettings.relative_to(root)),
                    remediation="Set BotAuthorization to a long random secret; never commit appsettings.json.",
                )
            )

    for path in walk_source(root):
        if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".cs", ".lua", ".json", ".html"}:
            continue
        rel = str(path.relative_to(root))
        text = read_text(path)
        if not text:
            continue

        for wh in WEBHOOK_RE.findall(text):
            if "node_modules" in rel:
                continue
            clientish = any(
                x in rel.lower()
                for x in ("2016-roblox", "public/", "pages/", "components/", "gameserver.lua", "client")
            )
            if clientish or path.suffix.lower() == ".lua":
                report.add(
                    Finding(
                        id="discord-webhook-in-tree",
                        severity="high",
                        title="Discord webhook URL in source",
                        detail="Anyone with the repo or view-source can abuse the webhook.",
                        evidence=f"{rel} (webhook id present)",
                        remediation="Remove from client/lua; use server-side env only; rotate webhook in Discord.",
                    )
                )
                break

        if path.name == "GameServer.lua" or path.name.endswith("GameServer.lua"):
            if "discord.com/api/webhooks" in text:
                report.add(
                    Finding(
                        id="gameserver-webhook",
                        severity="high",
                        title="Hardcoded webhook in game server lua",
                        detail="RCC/game-server can POST player events to a public webhook URL.",
                        evidence=rel,
                        remediation="Delete webhook from lua; use server-side logging without secrets in places.",
                    )
                )

        if "PlaceLauncher" in text and re.search(r"userSession\?\.\w+\s*\?\?\s*1", text):
            report.add(
                Finding(
                    id="place-launcher-user-1-fallback",
                    severity="critical",
                    title="Place launcher defaults to user id 1",
                    detail="Anonymous joins may run as the owner account.",
                    evidence=rel,
                    remediation="Require a valid ticket/session; never default userId to 1.",
                )
            )

        if "HttpPostBypass" in text and "marketplace/purchase" in text:
            report.add(
                Finding(
                    id="csrf-bypass-marketplace",
                    severity="high",
                    title="Marketplace purchase skips CSRF middleware",
                    detail="Cross-site purchase requests may be possible while victims are logged in.",
                    evidence=rel,
                    remediation="Remove marketplace/purchase from CSRF bypass list.",
                )
            )

        if "buildersclub/membership" in text and "HttpPostBypass" in text:
            report.add(
                Finding(
                    id="free-membership-route",
                    severity="critical",
                    title="Builders Club membership route on CSRF bypass list",
                    detail="Logged-in users may upgrade membership without payment checks in this fork.",
                    evidence=rel,
                    remediation="Gate membership on payment/admin; require CSRF.",
                )
            )

        if "botapi/resetpassword" in text and "randomlyGeneratedPassword" in text:
            report.add(
                Finding(
                    id="bot-resetpassword-returns-password",
                    severity="critical",
                    title="Bot API returns new password in response body",
                    detail="Combined with a leaked BotAuthorization this is instant account takeover.",
                    evidence=rel,
                    remediation="Never return passwords from APIs; use email/discord DM flow only.",
                )
            )

        if "GetAllowedSecurityKeys" in text and re.search(r"return\s+true\s*;", text):
            report.add(
                Finding(
                    id="client-integrity-disabled",
                    severity="high",
                    title="Client security key check always passes",
                    detail="Modified clients and executors are not rejected.",
                    evidence=rel,
                    remediation="Implement real client hash/version checks or accept in-game exploit risk.",
                )
            )

        if "ChatFilter" in text and "Hi gu" in text:
            report.add(
                Finding(
                    id="fake-chat-filter",
                    severity="medium",
                    title="Chat filter returns static placeholder text",
                    detail="Profanity and XSS in chat may not be filtered.",
                    evidence=rel,
                    remediation="Wire a real filter or disable chat.",
                )
            )

        if "RbxTempBypassFor18PlusAssets" in text:
            report.add(
                Finding(
                    id="18plus-header-bypass",
                    severity="high",
                    title="Header bypass for 18+ assets",
                    detail="Age-gated content can be fetched with a custom header.",
                    evidence=rel,
                    remediation="Remove RbxTempBypassFor18PlusAssets; enforce session age checks only.",
                )
            )

        if "Setting/QuietGet" in text and "AllowedQuietGetJson" not in text and path.suffix == ".cs":
            report.add(
                Finding(
                    id="quietget-no-allowlist",
                    severity="critical",
                    title="QuietGet may read arbitrary JSON paths (original ECS)",
                    detail="Path traversal via {type} parameter is a known file read issue.",
                    evidence=rel,
                    remediation="Allow-list QuietGet types like Bubbablox fork does.",
                )
            )

        if "validate-and-add-cookie" in rel:
            report.add(
                Finding(
                    id="frontend-cookie-setter",
                    severity="high",
                    title="Next.js route sets .ROBLOSECURITY from POST body",
                    detail="If CSRF key is default, sessions can be planted cross-site.",
                    evidence=rel,
                    remediation="Rotate serverRuntimeConfig csrfKey; restrict this route to trusted flows.",
                )
            )

        for pid, pat, msg in CREDENTIAL_STEALER_PATTERNS:
            if "ecs-audit" in rel:
                continue
            if not pat.search(text):
                continue
            if pid == "fetch-hook-login" and not re.search(
                r"password|passwd|passwordPresent|\bpass\b", text, re.I
            ):
                continue
            report.add(
                Finding(
                    id=f"trust-{pid}",
                    severity="critical" if "password" in pid or "pass-field" in pid else "high",
                    title="Suspicious credential telemetry (RAT indicator)",
                    detail=msg,
                    evidence=rel,
                    remediation="Remove browser hooks; never send passwords off-box. Use ecs-audit --trust-only after patching.",
                )
            )
            break

    config_examples = list(root.rglob("config.example.json")) + list(root.rglob("config.json"))
    for cfg in config_examples:
        if "2016-roblox" not in str(cfg) and "comblox-client" not in str(cfg):
            continue
        t = read_text(cfg)
        if "csrfKey" in t and "2NekqgcpRg4" in t:
            report.add(
                Finding(
                    id="frontend-example-csrf-key",
                    severity="medium",
                    title="Example CSRF key still in frontend config",
                    detail="Multi-instance or cookie-setter CSRF may be weak.",
                    evidence=str(cfg.relative_to(root)),
                    remediation="Generate a new csrfKey per deployment.",
                )
            )


ECS_SITE_MARKERS = (
    "economy simulator",
    "bubbablox",
    "2016-roblox",
    "roblox",
    "negotiate.ashx",
)


def normalize_target_url(raw: str) -> str:
    """Accept bare domains (example.com) or full https URLs; returns origin only."""
    s = raw.strip()
    if not s:
        raise ValueError("empty target")
    if "://" not in s:
        s = "https://" + s
    parsed = urllib.parse.urlparse(s)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must use http or https")
    host = parsed.hostname
    if not host:
        raise ValueError("missing domain")
    port = parsed.port
    netloc = host if port is None else f"{host}:{port}"
    return f"{parsed.scheme}://{netloc}".rstrip("/")


def http_get(url: str, timeout: float = 12.0) -> tuple[int, dict[str, str], bytes]:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "ECS-Audit/1.0 (+local security check; no exploit)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(64_000)
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        body = e.read(64_000) if e.fp else b""
        return e.code, headers, body
    except Exception:
        return 0, {}, b""


def scan_url(base: str, report: AuditReport) -> None:
    base = base.rstrip("/")
    report.target_url = base

    # Official patcher presence is the first thing we judge. Missing = host is unprotected.
    cert_url = f"{base}/.well-known/ecs-security.json"
    cert_status, _, cert_body = http_get(cert_url)
    cert_txt = cert_body.decode("utf-8", errors="ignore") if cert_body else ""
    official = False
    if cert_status == 200 and cert_txt.strip():
        low = cert_txt.lower()
        if any(
            x in low
            for x in (
                "auto-security-patcher",
                "ecs-security",
                "pengyni",
                "patcher_integrity",
                "official",
                "compliant",
            )
        ):
            official = True
            report.add(
                Finding(
                    id="remote-official-patcher-ok",
                    severity="info",
                    title="Official security patcher certification found",
                    detail=(
                        ".well-known/ecs-security.json is present and looks like an official patcher mark. "
                        "Host still needs the rest of the checklist, but this is the minimum owners must ship."
                    ),
                    evidence=cert_url,
                )
            )
    if not official:
        # Also poke common transparency paths.
        alt_hits = 0
        for alt in (
            f"{base}/ecs-host-compliance.json",
            f"{base}/patch-transparency.json",
            f"{base}/security-hardening-report.json",
        ):
            st, _, body = http_get(alt)
            if st == 200 and body:
                alt_hits += 1
        if alt_hits == 0:
            report.add(
                Finding(
                    id="remote-no-official-patcher",
                    severity="critical",
                    title="UNPROTECTED: official auto-security-patcher NOT detected",
                    detail=(
                        "No /.well-known/ecs-security.json, ecs-host-compliance.json, patch-transparency.json, "
                        "or security-hardening-report.json. This revival is advertising itself as an unpatched "
                        "ECS-family host. Randoms with the public leak playbook will treat you as free loot: "
                        "owner cookie forgery, bot password resets, DEBUG account factories, webhook theft, "
                        "economy prints. Until you run https://github.com/pengyni/auto-security-patcher your "
                        "admin account, player base, and Discord are on a timer."
                    ),
                    evidence="missing official patcher certification files",
                )
            )
        else:
            report.add(
                Finding(
                    id="remote-partial-hardening-only",
                    severity="critical",
                    title="Hardening leftovers found but official patcher certification missing",
                    detail=(
                        "Some security report files exist, but /.well-known/ecs-security.json from the official "
                        "auto-security-patcher was not found. Half-patched ECS hosts are still owned daily. "
                        "Players and rival hosts will not trust you until the official mark is present."
                    ),
                    evidence=f"partial files={alt_hits}; missing {cert_url}",
                )
            )

    probes: list[tuple[str, str, str, str]] = [
        (
            "negotiate-cookie-plant",
            "critical",
            "Login negotiate accepts suggest query",
            f"{base}/login/negotiate.ashx?suggest=ecs-audit-probe",
        ),
        (
            "bot-resetpassword-exposed",
            "critical",
            "Bot password reset route reachable",
            f"{base}/botapi/resetpassword?userId=1",
        ),
        (
            "bot-migrate-exposed",
            "high",
            "Bot asset migrate route reachable",
            f"{base}/botapi/migrate-alltypes?url=https://example.com",
        ),
        (
            "bot-coinflip-exposed",
            "high",
            "Bot coinflip / currency route reachable",
            f"{base}/botapi/discord/coinflip",
        ),
        (
            "bot-tickets-exposed",
            "high",
            "Bot user ticket dump route reachable",
            f"{base}/botapi/tickets/user/1",
        ),
        (
            "debug-integration-account",
            "critical",
            "DEBUG integration account route exposed",
            f"{base}/integration-test/create-account-and-set-cookie",
        ),
        (
            "get-join-script-debug",
            "critical",
            "DEBUG join script generator exposed",
            f"{base}/game/get-join-script-debug?placeId=1",
        ),
        (
            "get-join-script",
            "high",
            "Join script endpoint reachable",
            f"{base}/game/get-join-script?placeId=1",
        ),
        (
            "place-launcher",
            "high",
            "PlaceLauncher endpoint reachable",
            f"{base}/game/PlaceLauncher.ashx?placeId=1",
        ),
        (
            "allowed-security-keys",
            "high",
            "GetAllowedSecurityKeys response",
            f"{base}/GetAllowedSecurityKeys",
        ),
        (
            "marketplace-purchase-options",
            "high",
            "Marketplace purchase endpoint exists (POST not attempted)",
            f"{base}/marketplace/purchase",
        ),
        (
            "builders-club-membership",
            "high",
            "Builders Club membership endpoint reachable",
            f"{base}/buildersclub/membership",
        ),
        (
            "quiet-get-settings",
            "high",
            "QuietGet-style settings endpoint reachable",
            f"{base}/Setting/QuietGet/1.json",
        ),
        (
            "debug-slash",
            "critical",
            "Bare /debug route reachable",
            f"{base}/debug",
        ),
        (
            "internal-slash",
            "high",
            "Bare /internal route reachable",
            f"{base}/internal",
        ),
        (
            "env-probe",
            "critical",
            "Public .env probe",
            f"{base}/.env",
        ),
        (
            "appsettings-probe",
            "critical",
            "Public appsettings.json probe",
            f"{base}/appsettings.json",
        ),
    ]

    for fid, severity, title, url in probes:
        status, headers, body = http_get(url)
        if status == 0:
            report.add(
                Finding(
                    id=f"remote-unreachable-{fid}",
                    severity="info",
                    title=f"Could not reach: {title}",
                    detail="Host down, blocked, or TLS error during read-only probe.",
                    evidence=url,
                )
            )
            continue

        body_s = body.decode("utf-8", errors="ignore")[:800]
        if fid == "negotiate-cookie-plant":
            if "set-cookie" in headers and "roblosecurity" in headers.get("set-cookie", "").lower():
                report.add(
                    Finding(
                        id="remote-negotiate-set-cookie",
                        severity="critical",
                        title=title,
                        detail=(
                            "Server set .ROBLOSECURITY from the suggest= query on negotiate.ashx. "
                            "That is live session planting: whatever token is in the URL becomes the browser session cookie."
                        ),
                        evidence=f"HTTP {status}; Set-Cookie present for .ROBLOSECURITY",
                    )
                )
            elif status == 200:
                report.add(
                    Finding(
                        id="remote-negotiate-200",
                        severity="high",
                        title="negotiate.ashx returns 200",
                        detail=(
                            "Login negotiate is live and returned 200. On ECS forks this path usually still accepts "
                            "suggest= under some clients even when this probe did not observe Set-Cookie."
                        ),
                        evidence=f"HTTP {status}",
                    )
                )

        elif fid == "bot-resetpassword-exposed":
            if status == 200 and ("password" in body_s.lower() or "success" in body_s.lower()):
                report.add(
                    Finding(
                        id="remote-bot-reset-unauth",
                        severity="critical",
                        title="Unauthenticated bot password reset may work",
                        detail=(
                            "botapi/resetpassword answered like a successful reset and/or password return "
                            "without this scanner supplying a bot secret. On Bubbablox-family code that means "
                            "arbitrary userId password resets with the new password in JSON."
                        ),
                        evidence=f"HTTP {status}",
                    )
                )
            elif status in (401, 403):
                report.add(
                    Finding(
                        id="remote-bot-reset-blocked",
                        severity="info",
                        title="Bot reset route present but blocked for anonymous probe",
                        detail=(
                            f"HTTP {status}. Route exists. On many hosts BotAuthorization is still the public "
                            "leak default, so a blocked anonymous probe does not mean the reset oracle is gone."
                        ),
                        evidence=url,
                    )
                )
            elif status == 200:
                report.add(
                    Finding(
                        id="remote-bot-reset-200",
                        severity="high",
                        title="Bot password reset returned HTTP 200",
                        detail=(
                            "Reset route is live. Even without an obvious password field in this snippet, "
                            "ECS bot reset handlers commonly mutate credentials for the given userId."
                        ),
                        evidence=f"HTTP {status}",
                    )
                )

        elif fid == "debug-integration-account":
            if status == 200 and "created user" in body_s.lower():
                report.add(
                    Finding(
                        id="remote-debug-account-factory",
                        severity="critical",
                        title="DEBUG account factory is live",
                        detail=(
                            "Public DEBUG helper created an account and/or session cookie. "
                            "This is an account vending machine left over from development builds."
                        ),
                        evidence=url,
                    )
                )
            elif status == 200:
                report.add(
                    Finding(
                        id="remote-debug-account-200",
                        severity="high",
                        title="DEBUG integration account route returned 200",
                        detail="integration-test account helper is reachable on the public host.",
                        evidence=f"HTTP {status}",
                    )
                )

        elif fid == "get-join-script-debug":
            if status == 200 and "ticket" in body_s.lower():
                report.add(
                    Finding(
                        id="remote-debug-join-ticket",
                        severity="critical",
                        title="DEBUG join ticket minting is live",
                        detail=(
                            "Debug join generator returned ticket material. On ECS, tickets often embed "
                            "session JWTs or authenticationTicket values reusable as site logins."
                        ),
                        evidence=url,
                    )
                )
            elif status == 200:
                report.add(
                    Finding(
                        id="remote-debug-join-200",
                        severity="high",
                        title="DEBUG join script endpoint returned 200",
                        detail="Debug join helper is publicly reachable.",
                        evidence=f"HTTP {status}",
                    )
                )

        elif fid == "get-join-script":
            if status == 200 and ("ticket" in body_s.lower() or "placeLauncher" in body_s or "authentication" in body_s.lower()):
                report.add(
                    Finding(
                        id="remote-join-script-ticket",
                        severity="high",
                        title="Join script endpoint returns launcher/ticket material",
                        detail=(
                            "Non-debug join script answered with ticket or launcher fields. "
                            "If those fields include session material, anyone who can hit the URL can steal accounts."
                        ),
                        evidence=f"HTTP {status}",
                    )
                )

        elif fid == "allowed-security-keys":
            if status == 200 and body_s.strip().lower() in ("true", '{"data":true}'):
                report.add(
                    Finding(
                        id="remote-security-keys-true",
                        severity="high",
                        title="GetAllowedSecurityKeys allows all clients",
                        detail=(
                            "Client integrity gate returned unrestricted/true. Modified clients and executors "
                            "are not rejected at this HTTP check."
                        ),
                        evidence=body_s[:120],
                    )
                )

        elif fid == "bot-migrate-exposed" and status == 200:
            report.add(
                Finding(
                    id="remote-bot-migrate-200",
                    severity="high",
                    title="Bot migrate returned HTTP 200",
                    detail=(
                        "migrate-alltypes is live. This family of routes fetches attacker-chosen URLs into the "
                        "asset pipeline (SSRF + content injection) when bot auth is weak or DEBUG."
                    ),
                    evidence=url,
                )
            )

        elif fid == "bot-coinflip-exposed" and status in (200, 400, 401, 403, 405):
            report.add(
                Finding(
                    id="remote-bot-coinflip-present",
                    severity="high" if status == 200 else "medium",
                    title="Bot coinflip / currency route is present",
                    detail=(
                        f"HTTP {status}. Discord coinflip bot routes on ECS forks mint or spend robux for a "
                        "discord id when BotAuthorization is known or bypassed."
                    ),
                    evidence=url,
                )
            )

        elif fid == "marketplace-purchase-options" and status not in (404, 0):
            report.add(
                Finding(
                    id="remote-marketplace-present",
                    severity="high" if status == 200 else "medium",
                    title="Marketplace purchase endpoint is reachable",
                    detail=(
                        f"HTTP {status}. Purchase surface exists. On many forks this route is CSRF-exempt and "
                        "becomes forced-buy / economy griefing against logged-in players. Unpatched hosts "
                        "bleed limiteds and balances until the economy is a joke."
                    ),
                    evidence=url,
                )
            )

        elif fid == "builders-club-membership" and status not in (404, 0):
            report.add(
                Finding(
                    id="remote-buildersclub-present",
                    severity="high" if status == 200 else "medium",
                    title="Builders Club membership endpoint is reachable",
                    detail=(
                        f"HTTP {status}. Membership grant routes on ECS forks are often CSRF-bypassed and "
                        "sometimes skip payment checks, so attackers self-grant paid tiers."
                    ),
                    evidence=url,
                )
            )

        elif fid == "quiet-get-settings" and status == 200 and body_s.strip():
            report.add(
                Finding(
                    id="remote-quietget-200",
                    severity="high",
                    title="QuietGet-style settings endpoint returned data",
                    detail=(
                        "Settings QuietGet answered with a body. Original ECS QuietGet without an allow-list "
                        "could be steered into reading sensitive JSON paths."
                    ),
                    evidence=f"HTTP {status}; body length {len(body_s)}",
                )
            )

        elif fid == "bot-tickets-exposed" and status not in (404, 0):
            report.add(
                Finding(
                    id="remote-bot-tickets-present",
                    severity="critical" if status == 200 else "high",
                    title="Bot ticket / user dump route is present",
                    detail=(
                        f"HTTP {status}. botapi ticket routes on ECS forks dump user records tied to discord ids "
                        "or user ids when bot auth is weak. That is doxxing + account pivoting material."
                    ),
                    evidence=url,
                )
            )

        elif fid == "place-launcher" and status not in (404, 0):
            report.add(
                Finding(
                    id="remote-placelauncher-present",
                    severity="high" if status == 200 else "medium",
                    title="PlaceLauncher endpoint is reachable",
                    detail=(
                        f"HTTP {status}. PlaceLauncher on Bubbablox-family code has historically fallen back to "
                        "userId 1 (owner) and stuffed session tickets into join URLs."
                    ),
                    evidence=url,
                )
            )

        elif fid == "debug-slash" and status == 200:
            report.add(
                Finding(
                    id="remote-debug-slash",
                    severity="critical",
                    title="Public /debug route is live",
                    detail=(
                        "A bare /debug path answered 200. On ECS clones this usually means development tooling, "
                        "stack dumps, or internal toggles are still networked to the world."
                    ),
                    evidence=url,
                )
            )

        elif fid == "internal-slash" and status == 200:
            report.add(
                Finding(
                    id="remote-internal-slash",
                    severity="high",
                    title="Public /internal route is live",
                    detail=(
                        "A bare /internal path answered 200. Internal admin/RCC helpers do not belong on the public edge."
                    ),
                    evidence=url,
                )
            )

        elif fid == "env-probe" and status == 200 and body_s.strip():
            # Only flag if it looks like env content, not an HTML soft-404.
            if ("=" in body_s and not body_s.lstrip().lower().startswith("<!")) or "APP_" in body_s or "Jwt" in body_s:
                report.add(
                    Finding(
                        id="remote-env-exposed",
                        severity="critical",
                        title="Public .env (or env-like secret file) is downloadable",
                        detail=(
                            "The host served what looks like environment/secret material at /.env. "
                            "That is usually every database password, JWT key, and bot secret in one file. "
                            "Owner takeover is immediate once this is indexed or shared."
                        ),
                        evidence=f"HTTP {status}; body length {len(body_s)}",
                    )
                )

        elif fid == "appsettings-probe" and status == 200 and ("Jwt" in body_s or "Authorization" in body_s or "ConnectionString" in body_s):
            report.add(
                Finding(
                    id="remote-appsettings-exposed",
                    severity="critical",
                    title="Public appsettings.json with secrets is downloadable",
                    detail=(
                        "appsettings.json is web-reachable and contains auth-shaped keys. "
                        "This is the classic ECS leak layout left on a live reverse proxy. "
                        "Session forgery and bot API takeover follow directly from reading this file."
                    ),
                    evidence=f"HTTP {status}",
                )
            )

    status, _, home = http_get(base + "/")
    if status == 200:
        home_s = home.decode("utf-8", errors="ignore")
        if not any(m in home_s.lower() for m in ECS_SITE_MARKERS):
            report.add(
                Finding(
                    id="remote-maybe-not-ecs",
                    severity="info",
                    title="Site may not be an Economy Simulator / ECS revival",
                    detail=(
                        "Homepage did not match common ECS markers. Probes still ran. "
                        "Critical hits below should still be treated seriously on restyled forks."
                    ),
                    evidence=base,
                )
            )
        if "10000000-ffff-ffff-ffff-000000000001" in home_s:
            report.add(
                Finding(
                    id="remote-hcaptcha-test-key",
                    severity="medium",
                    title="hCaptcha test sitekey in HTML",
                    detail=(
                        "Public hCaptcha test sitekey is embedded. Automation always passes, so register/login "
                        "and other gated forms are bot-open."
                    ),
                    evidence="homepage HTML",
                )
            )
        if WEBHOOK_RE.search(home_s):
            report.add(
                Finding(
                    id="remote-webhook-in-html",
                    severity="critical",
                    title="Discord webhook in public HTML",
                    detail=(
                        "A Discord webhook URL is visible to anyone who loads the page or JS bundle. "
                        "That secret can be spammed or used to spoof the host's alert channel."
                    ),
                    evidence="homepage HTML",
                )
            )
        lower = home_s.lower()
        if "hello world" in lower or "yourverysecuresessionskey" in lower:
            report.add(
                Finding(
                    id="remote-weak-secret-echo",
                    severity="critical",
                    title="Leak-style secret placeholder appears in public HTML",
                    detail=(
                        "Homepage/JS echoes a known weak secret placeholder pattern from ECS examples. "
                        "If the real session key matches, cookies can be forged for any user id."
                    ),
                    evidence="homepage HTML",
                )
            )
        if "/_next/" in home_s or "2016-roblox" in lower or "roblox-client" in lower:
            unprotected = any(f.id in ("remote-no-official-patcher", "remote-partial-hardening-only") for f in report.findings)
            report.add(
                Finding(
                    id="remote-ecs-frontend-fingerprint",
                    severity="critical" if unprotected else "high",
                    title="2016 / Next ECS-style frontend fingerprint",
                    detail=(
                        "Frontend shape matches the usual 2016-roblox-main / Next ECS client tree. "
                        + (
                            "Combined with NO official auto-security-patcher mark, this host is a textbook target: "
                            "negotiate cookie planting, example csrfKey cookie setters, join tickets in GET URLs, "
                            "and the entire public leak playbook. Owners who leave this online unpatched lose "
                            "admin within days, sometimes hours of being posted."
                            if unprotected
                            else "Official patcher mark was seen, but frontend-shaped risks can still remain if the patcher was not actually applied."
                        )
                    ),
                    evidence="homepage HTML",
                )
            )

        # Missing security headers = soft signal that host never hardened the edge.
        status_h, headers_h, _ = http_get(base + "/")
        if status_h == 200:
            missing = []
            for h in ("content-security-policy", "x-frame-options", "strict-transport-security", "x-content-type-options"):
                if h not in headers_h:
                    missing.append(h)
            if len(missing) >= 3:
                report.add(
                    Finding(
                        id="remote-missing-security-headers",
                        severity="medium",
                        title="Edge security headers mostly missing",
                        detail=(
                            "Browser security headers are largely absent ("
                            + ", ".join(missing)
                            + "). That matches stock ECS reverse-proxy deploys that never ran a real hardener. "
                            "Clickjacking and mixed-content session theft become trivial add-ons to the bigger auth bugs."
                        ),
                        evidence="response headers on /",
                    )
                )


def print_summary(report: AuditReport) -> None:
    counts = report.counts()
    print()
    print(f"ECS Security Scan v{report.version}  {report.scanned_at}")
    if report.source_root:
        print(f"  source: {report.source_root}")
    if report.target_url:
        print(f"  url:    {report.target_url}")
    print(f"  findings: {len(report.findings)}  ({counts})")
    print()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(report.findings, key=lambda x: (order.get(x.severity, 9), x.id)):
        print(f"[{f.severity.upper()}] {f.id}")
        print(f"  {f.title}")
        if f.evidence:
            print(f"  evidence: {f.evidence}")
        if f.remediation:
            print(f"  fix: {f.remediation}")
        print()
    if report.target_url:
        print("Stay protected on your own host:")
        print("  https://github.com/pengyni/auto-security-patcher")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read-only ECS / Economy Simulator vulnerability scanner for any public site URL.",
        epilog="Examples:\n"
        "  ecs-audit.py -u myrevival.com\n"
        "  ecs-audit.py --url https://myrevival.com --json report.json\n"
        "  ecs-audit.py --source ./ecs-tree\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--source", type=Path, help="Optional: path to ECS/Bubbablox source on disk")
    parser.add_argument(
        "-u",
        "--url",
        "--domain",
        dest="url",
        metavar="DOMAIN_OR_URL",
        type=str,
        help="Any public ECS revival: bare domain (example.com) or https:// URL",
    )
    parser.add_argument("--json", type=Path, help="Write full JSON report to this file")
    parser.add_argument(
        "--trust-only",
        action="store_true",
        help="Only report RAT/credential-stealer patterns (for verifying a patcher)",
    )
    args = parser.parse_args()

    if not args.source and not args.url:
        parser.error("Provide --source and/or --url")

    report = AuditReport()
    if args.source:
        if not args.source.exists():
            raise SystemExit(f"missing source: {args.source}")
        scan_source(args.source.resolve(), report)
    if args.url:
        try:
            normalized = normalize_target_url(args.url)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        scan_url(normalized, report)

    if args.trust_only:
        report.findings = [f for f in report.findings if f.id.startswith("trust-") or "RAT" in f.title]

    # de-dupe by id+evidence
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for f in report.findings:
        key = (f.id, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    report.findings = unique

    print_summary(report)

    if args.json:
        counts = report.counts()
        critical = counts.get("critical", 0)
        high = counts.get("high", 0)
        risk = min(100, critical * 22 + high * 10 + counts.get("medium", 0) * 4 + counts.get("low", 0))
        unprotected = any(f.id in ("remote-no-official-patcher", "remote-partial-hardening-only") for f in report.findings)
        args.json.write_text(
            json.dumps(
                {
                    **{k: v for k, v in asdict(report).items() if k != "findings"},
                    "findings": [asdict(f) for f in report.findings],
                    "counts": counts,
                    "risk_score": risk,
                    "unprotected": unprotected,
                    "required_patcher": "https://github.com/pengyni/auto-security-patcher",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"JSON report: {args.json}")

    critical = sum(1 for f in report.findings if f.severity == "critical")
    if critical:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
