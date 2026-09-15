"""Stock Economy Simulator / Bubbablox vulnerabilities before official auto-security-patcher.

Injected wholesale when a live host has no official patcher certification.
Severities match the ECS vuln rundown cheat sheet.
"""
from __future__ import annotations

# Each row: id, severity, tag, title, abuse_detail, why_it_matters
UNPATCHED_ECS_CATALOG: list[tuple[str, str, str, str, str, str]] = [
    (
        "baseline-jwt-weak-default",
        "critical",
        "account-takeover",
        "Default / leaked JWT session secret (Jwt.Sessions)",
        "Stock ECS ships Jwt.Sessions as values like hello world 12345. .ROBLOSECURITY is just a JWT signed with that key.\n\n"
        "Anyone who knows the default can mint a cookie for user id 1 (owner on almost every install guide) and walk into full admin: password changes, item grants, bans, economy wipes, staff panels. Owner bypasses staff permission checks, so one forged cookie is god mode.",
        "This single default is why unpatched ECS hosts lose admin within hours of being posted.",
    ),
    (
        "baseline-shared-leaked-auth-string",
        "critical",
        "secrets",
        "Bot / RCC / GameServer auth share one leaked string",
        "Original appsettings uses ONE public string for BotAuthorization, RccAuthorization, and GameServerAuthorization.\n\n"
        "That is not four locks. It is one lock with four doors: bot password reset, RCC callbacks, datastore access, game-server join/leave ticket printers, asset gates. The string is in the public GitHub leak forever.",
        "Every privileged automation surface becomes public knowledge on stock deploys.",
    ),
    (
        "baseline-negotiate-cookie-plant",
        "critical",
        "account-takeover",
        "login/negotiate.ashx plants .ROBLOSECURITY from suggest=",
        "Negotiate takes suggest= from the query string and writes it straight into the session cookie.\n\n"
        "Abuse: install a forged JWT without a real login form, phishing redirects that lock a victim into an attacker session, tickets sitting in URLs/history/proxies/Discord. This is the install step after cookie forgery.",
        "Main mass account-takeover on-ramp on ECS clones.",
    ),
    (
        "baseline-bot-resetpassword-oracle",
        "critical",
        "account-takeover",
        "botapi/resetpassword returns the new password in JSON",
        "Bubbablox-family bot reset takes userId, regenerates the password, and returns it in the response body. Auth is BotAuthorization (leaked / DEBUG-skipped).\n\n"
        "Abuse: target userId 1, hit the route with the known key, receive a working owner password. Not a Discord DM flow. The API is the credential drop.",
        "Instant owner takeover on any host that left bot auth default.",
    ),
    (
        "baseline-place-launcher-user-1",
        "critical",
        "account-takeover",
        "PlaceLauncher falls back to user id 1 (owner)",
        "When ticket/session is missing, Bubbablox PlaceLauncher sets userId = 1.\n\n"
        "Abuse: join games as the owner character. Creator-only scripts, admin tools, and place permissions treat the attacker as place owner inside the server.",
        "Anonymous joins become owner joins. Every in-game trust assumption dies.",
    ),
    (
        "baseline-free-builders-club",
        "critical",
        "economy",
        "Free Builders Club / membership grant (CSRF bypass, no payment)",
        "POST buildersclub/membership is on the CSRF bypass list. Logged-in callers set BC/TBC/OBC, get badges, and unlock daily robux payouts with no payment check.\n\n"
        "Abuse: every account becomes OBC. Daily faucet. Rare badges worthless. Economy is fake on day one.",
        "Kills the entire point of an Economy Simulator revival.",
    ),
    (
        "baseline-rcc-soap-unauth",
        "critical",
        "rcc-rce",
        "RCC SOAP has no real user auth",
        "RCCService accepts OpenJob / OpenJobEx SOAP and runs lua. ECS talks to it on a local port; hosts often bind or port-forward it.\n\n"
        "Abuse: arbitrary game-server lua, dump datastores/chats, load malicious places, use HttpService as a proxy, native breakout risk on old RCC builds.",
        "Exposed RCC is how Windows boxes get mined and places get overwritten.",
    ),
    (
        "baseline-quietget-path-traversal",
        "critical",
        "secrets",
        "QuietGet path traversal (original ECS, no allow-list)",
        "Setting/QuietGet/{type} does Path.Combine into a json dir with no allow-list on original ECS.\n\n"
        "Abuse: walk out of the settings folder and read other files the process can read: configs, secrets, sometimes source.",
        "Client settings endpoint becomes a file reader.",
    ),
    (
        "baseline-debug-account-factory",
        "critical",
        "account-takeover",
        "DEBUG integration-test account factory",
        "/integration-test/create-account-and-set-cookie creates users (often with builders club), auto-approves, sets session cookies. get-join-script-debug mints tickets from privileged user ids.\n\n"
        "Abuse: public staff/account vending if anyone ships a DEBUG build (common).",
        "DEBUG left online is a give-me-admin button.",
    ),
    (
        "baseline-postgres-in-appsettings",
        "critical",
        "secrets",
        "Database password and operator secrets in appsettings.json",
        "Stock leak commits postgres passwords, twitter keys, and auth strings next to Jwt.Sessions.\n\n"
        "Abuse: clone the repo or scrape a mis-deployed appsettings and own the database, the site, and burned third-party API accounts.",
        "The example config is a production keyring for anyone who did not rotate.",
    ),
    (
        "baseline-frontend-cookie-setter",
        "high",
        "account-takeover",
        "Next.js validate-and-add-cookie sets .ROBLOSECURITY from POST body",
        "2016 frontend route accepts a cookie in the body and sets it on the browser. CSRF depends on csrfKey from config.example that hosts rarely rotate.\n\n"
        "Abuse: plant attacker-chosen sessions cross-site when the example csrfKey is still live.",
        "Second session-planting path beside negotiate.",
    ),
    (
        "baseline-join-ticket-is-session",
        "high",
        "account-takeover",
        "Join tickets / authenticationTicket are the session JWT in URLs",
        "join.ashx and get-join-script stuff .ROBLOSECURITY / authenticationTicket into GET URLs and launcher JSON.\n\n"
        "Abuse: referrer leaks, Discord join links, screenshots, RCC logs, access logs. Classic revival cookie logs with zero fancy exploit.",
        "Pressing play hands out the account.",
    ),
    (
        "baseline-client-integrity-off",
        "high",
        "client",
        "GetAllowedSecurityKeys / MD5 checks disabled",
        "Bubbablox returns true / tiny hardcoded lists and skips real RCC-gated integrity. Comments admit it is insecure.\n\n"
        "Abuse: modified clients, injectors, 2016 executors attach freely. In-game economy remotes and FE-off places get farmed without a website 0day.",
        "Website green-lights every script kiddie client.",
    ),
    (
        "baseline-csrf-bypass-marketplace",
        "high",
        "economy",
        "marketplace/purchase on HttpPostBypass (CSRF off)",
        "Purchase is CSRF-exempt while still reading the logged-in session.\n\n"
        "Abuse: malicious pages force buys, drain balances, buy junk at max price while the victim stays logged into the revival.",
        "Logged-in players are unsafe in other browser tabs.",
    ),
    (
        "baseline-gs-auth-ticket-printer",
        "high",
        "economy",
        "GameServerAuthorization leak prints tickets on fake leave events",
        "Player-left reports pay tickets by minutes played. GameServerAuthorization is the public leak string on stock ECS.\n\n"
        "Abuse: spoof joins/leaves, farm tickets, convert to robux on the exchange. Same secret often fires Discord webhooks with live player tracking.",
        "Money printer with extra steps once GS auth is known.",
    ),
    (
        "baseline-discord-coinflip",
        "high",
        "economy",
        "botapi/discord/coinflip spends/prints robux",
        "Coinflip bets robux via bot auth, uses weak Random(), is often a GET.\n\n"
        "Abuse with leaked bot key: flip on accounts you do not own, grind EV, drain balances, prefetch/log amplification.",
        "Bot key becomes a remote economy grief tool.",
    ),
    (
        "baseline-migrate-ssrf",
        "high",
        "rcc-rce",
        "botapi/migrate-alltypes SSRF + asset injection",
        "Fetches caller-chosen URLs into the asset pipeline (images, audio, meshes, lua, models).\n\n"
        "Abuse: internal SSRF (localhost, cloud metadata), pull malicious rbxm/lua into catalog/game servers, bandwidth bombs.",
        "Site becomes an open fetch primitive and malware delivery pipe.",
    ),
    (
        "baseline-gameserver-webhook",
        "high",
        "secrets",
        "Hardcoded Discord webhook in GameServer.lua / client JS",
        "Stock trees embed webhook URLs in lua and frontend bundles.\n\n"
        "Abuse: view-source the secret, spam/nuke the channel, watch joins, or poison the only alert channel the host has. If someone logged passwords to Discord, those are public too.",
        "Webhooks in client/lua are not secrets. They are public write pipes.",
    ),
    (
        "baseline-fake-chat-filter",
        "high",
        "xss",
        "Chat filter is fake (echo / Hi gu placeholder)",
        "ChatFilter and moderation filter endpoints echo or return placeholders. Comments say add a real filter eventually.\n\n"
        "Abuse: unfiltered chat, XSS if any page renders chat/comments as HTML, safety nightmare on a kids-adjacent 2016 recreation.",
        "No real filter means chat is an XSS and abuse firehose.",
    ),
    (
        "baseline-18plus-header-bypass",
        "high",
        "privacy",
        "RbxTempBypassFor18PlusAssets header skips age gates",
        "A known header marks the requester as 18+ with no account check. Comments say to remove it.\n\n"
        "Abuse: download age-gated / unapproved assets. Leaked bot auth also disables encryption and moderation gates.",
        "Age gates become a shared password from the leak.",
    ),
    (
        "baseline-rcc-key-in-lua-urls",
        "high",
        "secrets",
        "RccAuthorization stuffed into lua templates and asset URLs",
        "apiKey appears in game server lua and /asset/?id=&apiKey= URLs.\n\n"
        "Abuse: read key from logs, join scripts, errors, or place source; then hit asset delivery and datastore endpoints as the renderer.",
        "RCC key cannot stay secret if it is shipped to every game server script.",
    ),
    (
        "baseline-http-bypass-lists",
        "high",
        "csrf",
        "HttpGetBypass / HttpPostBypass skip CSRF + app guard + proxy",
        "Custom attributes put routes on frontend proxy bypass, application guard allow list, AND CSRF bypass at once. Login, purchase, membership, datastores, badges, gs shutdown, bot APIs sit there.\n\n"
        "Abuse: cross-site state changes while logged in; GET-that-mutates from image tags.",
        "CSRF exists on paper. Half the money and auth surface opted out.",
    ),
    (
        "baseline-frontend-example-csrf-key",
        "high",
        "account-takeover",
        "Example frontend csrfKey still in config",
        "config.example.json ships a shared csrfKey (e.g. 2NekqgcpRg4 pattern). Hosts copy it forever.\n\n"
        "Abuse: forge frontend CSRF for cookie-setter and other protected Next routes.",
        "Example CSRF key makes CSRF theater.",
    ),
    (
        "baseline-non-httponly-reset-cookies",
        "medium",
        "account-takeover",
        "Password reset / login cookies without HttpOnly (SameSite None)",
        "resetpasswordverified and some login cookies are readable by JavaScript / cross-site.\n\n"
        "Abuse: any XSS finishes reset/session dances by reading those flags.",
        "XSS becomes full account compromise faster.",
    ),
    (
        "baseline-daily-payout-alt-farms",
        "medium",
        "economy",
        "Daily login / visit payouts without real alt resistance",
        "Daily tickets, place visit payouts, homestead/bricksmith thresholds.\n\n"
        "Abuse: alt farms and visit bots; with leaked GS auth this automates. Limiteds inflate until worthless.",
        "Soft economy faucets without identity guarantees.",
    ),
    (
        "baseline-client-trusted-gamepass",
        "medium",
        "economy",
        "In-game purchases / remotes trust the 2016 client too much",
        "Game passes and products go through marketplace paths the 2016 client calls. Classic places do client-says-bought-give-gear.\n\n"
        "Abuse: fire remotes for free gear/currency without a website bug.",
        "You inherited every bad 2016 place economy on top of site bugs.",
    ),
    (
        "baseline-asset-proxy-roblox",
        "medium",
        "rcc-rce",
        "Asset endpoint proxies to remote AssetUrl and caches bytes",
        "Missing local assets fetch from configured AssetUrl and cache.\n\n"
        "Abuse: disk/bandwidth bombs, SSRF-ish depending on AssetUrl, sneak unreviewed assets onto the revival.",
        "Unpatched asset proxy is a content and availability risk.",
    ),
    (
        "baseline-asset-validator-no-auth",
        "medium",
        "rcc-rce",
        "AssetValidationServiceV2 has no auth",
        "/api/v1/validate-place and validate-item take raw bodies with no key.\n\n"
        "Abuse: DOS the parser with giant places; crafted files that blow up an unsandboxed validator.",
        "Unauthenticated parser on the network is free attack surface.",
    ),
    (
        "baseline-filtering-enabled-off",
        "medium",
        "client",
        "FilteringEnabled / FilterType off on common ECS places",
        "2016 FE transition era. Tons of places saved with filtering off.\n\n"
        "Abuse: local scripts replicate, spawn tools, walkspeed, unprotected leaderstats, GiveMoney remotes with huge amounts. Most free admin clips never need a website bug.",
        "FE-off places are why executors own every server.",
    ),
    (
        "baseline-httpservice-forced-on",
        "medium",
        "client",
        "HttpService forced on in renderer / GameServer scripts",
        "Renderer and GameServer lua enable HttpService and often embed webhooks.\n\n"
        "Abuse: malicious places phone home with player names and server-visible data.",
        "HttpEnabled plus webhook secrets is built-in exfil.",
    ),
    (
        "baseline-fflag-server-script-protection-off",
        "medium",
        "client",
        "FFlagServerScriptProtection false in shipped client settings",
        "Server script protection off plus loadstring flags hidden instead of disabled.\n\n"
        "Abuse: 2016 executor playground behavior on stock client settings.",
        "Shipped flags invite script hubs.",
    ),
    (
        "baseline-studio-login-bypass-route",
        "medium",
        "account-takeover",
        "Studio v2/login is another bypass-heavy login path",
        "Extra body parsing branches for studio vs website on a bypass route.\n\n"
        "Abuse: more code paths where a check gets skipped; still a live auth surface.",
        "Duplicate login stacks are where auth bugs hide.",
    ),
    (
        "baseline-persistence-log-before-auth",
        "medium",
        "secrets",
        "persistence/getv2 reads datastore values before IsRcc check",
        "Reads keys, prints to server console, then errors if not RCC.\n\n"
        "Abuse: pollute logs with secrets, timing/error oracles. If RCC key leaks, full DataStore read/write.",
        "Do not log datastore values. Unpatched ECS does.",
    ),
    (
        "baseline-allowedhosts-star",
        "medium",
        "csrf",
        "AllowedHosts * and host-header weakness",
        "Example configs allow all hosts.\n\n"
        "Abuse: host-header weirdness, cache poisoning adjacent issues, confused proxies.",
        "Stock edge config is wide open.",
    ),
    (
        "baseline-hcaptcha-test-keys",
        "medium",
        "account-takeover",
        "hCaptcha official test keys always pass",
        "Example public/private captcha keys are the always-pass test pair.\n\n"
        "Abuse: bot registration/login floods, spam, limited sniping, credential stuffing with no captcha cost.",
        "Captcha is decorative on stock deploys.",
    ),
    (
        "baseline-owner-userid-defaults",
        "medium",
        "account-takeover",
        "OwnerUserId defaults to 1 / small hardcoded owner lists",
        "OwnerUserId is 1 or lists like 1,12,16,74 from install folklore.\n\n"
        "Abuse: first registered or forged low ids inherit god mode without a setup token.",
        "Predictable owner ids make takeover targeting trivial.",
    ),
    (
        "baseline-ip-exposure",
        "medium",
        "privacy",
        "Player IPs sent to iphub / visible to game hosts",
        "Site and game servers handle raw player IPs; some join scripts historically hardcoded machine addresses.\n\n"
        "Abuse: harassment, weak IP bans, game owners seeing join origins.",
        "Privacy landmine every revival community already warns about.",
    ),
    (
        "baseline-xss-user-content",
        "medium",
        "xss",
        "XSS in forum / catalog / shouts / usernames (treat as real)",
        "2016 frontend is partly React but aspx-style pages, admin bundles, jquery, and raw dumps remain.\n\n"
        "Abuse: steal sessions via negotiate/cookie-setter, force purchases, plant fake login UI, hook CSRF tokens.",
        "XSS on this stack is cookie city.",
    ),
    (
        "baseline-badge-award-spoofable-rcc",
        "medium",
        "economy",
        "Badge award gated on RccAuthorization that is already public",
        "Award checks accesskey == RccAuthorization. Good idea, leaked key.\n\n"
        "Abuse: award any badge tied to a place; fake prestige; bypass badge-gated game logic.",
        "RCC key leak turns badges into a checkbox.",
    ),
    (
        "baseline-bot-skips-moderation",
        "medium",
        "privacy",
        "BotAuthorization disables encryption and 18+/moderation gates",
        "Matching bot auth header skips asset encryption and age/moderation checks.\n\n"
        "Abuse: download unapproved and 18+ assets hosts should not be serving publicly.",
        "Leaked bot key empties the moderated asset closet.",
    ),
    (
        "baseline-process-start-staff-tools",
        "medium",
        "rcc-rce",
        "Admin/web tools shell out via Process.Start",
        "Staff APIs start rbxmk, obj conversion, RCC, etc.\n\n"
        "Abuse: if arguments ever take user paths unsafely, command injection. Treat staff shell-outs as hostile until proven clean.",
        "Unpatched staff tooling is a privilege escalation magnet.",
    ),
    (
        "baseline-unsecured-content-folder",
        "low",
        "secrets",
        "UnsecuredContent served with no login",
        "Application guard allows UnsecuredContent on purpose.\n\n"
        "Abuse: hosts dump clients, places, keys, logs, temp zips there. The folder name is the warning.",
        "Public junk drawer for secrets and clients.",
    ),
    (
        "baseline-roproxy-redirect",
        "low",
        "privacy",
        "Missing product info redirects to economy.roproxy.com",
        "Not a full open redirect, but sends players to a third-party proxy.\n\n"
        "Abuse: proxy sees IPs, can serve junk, teaches clients to trust another host for assets.",
        "Third-party proxy in the critical asset path.",
    ),
    (
        "baseline-bbmons-weak-rng",
        "low",
        "account-takeover",
        "bbmons login codes use System.Random; DEBUG skips API key",
        "32-char codes via weak RNG; DEBUG skips redeem auth.\n\n"
        "Abuse: sister-site login-as-user issues if that ecosystem is still wired.",
        "Weak cross-game login codes on stock builds.",
    ),
    (
        "baseline-rsa-join-script-keys",
        "high",
        "account-takeover",
        "Join-script RSA private keys shipped with deploys",
        "Hosts often ship pem files used to sign join scripts.\n\n"
        "Abuse: forge join scripts and sit in games as whoever the ticket claims.",
        "Private signing keys in the tree forge presence in every place.",
    ),
]


def baseline_findings():
    """Return Finding-compatible dicts for JSON / AuditReport injection."""
    out = []
    for fid, severity, tag, title, detail, why in UNPATCHED_ECS_CATALOG:
        out.append(
            {
                "id": fid,
                "severity": severity,
                "tag": tag,
                "title": title,
                "detail": detail,
                "evidence": "Stock unpatched ECS / Bubbablox (no official auto-security-patcher)",
                "remediation": "",
                "why_it_matters": why,
                "abuse": detail,
            }
        )
    return out
