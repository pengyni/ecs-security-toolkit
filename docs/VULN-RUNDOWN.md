# ok so economy simulator / bubbablox is kinda cooked

full vulnerability rundown. written so a human can actually read it.

this is about the leaked Economy Simulator source (the 2016 roblox revival stack) and the Bubbablox forks that copied it. same family. 2016-roblox-main frontend, C# `Roblox.Website` backend, RCC, asset validation, game-server lua, the whole mess.

i am describing what is broken and what a bad person could do with it if they found it. this is not a how-to. if you host this source, fix the stuff. if you play on a random ecs clone, assume it is unsafe.

sources this was checked against:
- original Economy Simulator leak (`00f8/Economy-Simulator`)
- Bubbablox-v2 2021 branch (`harryzawg/bubbablox-v2`)
- the 2016 frontend tree people still run (including comblox-client, which is literally named "Roblox 2016 Frontend - ECS")

a lot of hosts copy the example configs and never rotate anything. that is why this source keeps getting people wrecked.

---

## 0. the big picture

ecs was never a hardened product. it is a revival kit that was published so people could self host 2016 roblox. the oldrobloxrevivals subreddit even banned helping people set it up because of how many holes are in it.

the stack has like four different "auth" secrets that are supposed to be different:
- session JWT (makes `.ROBLOSECURITY`)
- RCC access key (game servers talking to the site)
- game server authorization (gs ping / shutdown / player reports)
- bot api key (discord bot stuff)

in the original leak they are all the SAME string, sitting in `appsettings.json`, committed to git, next to a postgres password, twitter api keys, and a jwt secret that is literally `hello world 12345`.

if you did not change those, you do not have a website. you have a public admin panel with extra steps.

---

## 1. account takeover / stealing logins

these are the ones that actually steal people.

### 1.1 session secret in the repo (critical)

original ecs ships `Jwt.Sessions` as `hello world 12345`.

`.ROBLOSECURITY` is just a JWT signed with that key. if the key is the default (or leaked, or copied from a tutorial screenshot), anyone who understands jwt can mint a cookie for user id 1, who is almost always the owner.

abuse: full site takeover. change passwords, give items, empty the economy, ban everyone, dump the db from admin, whatever admin can do. owner bypasses staff permission checks too, so one forged cookie is god mode.

### 1.2 `/login/negotiate.ashx` sets the cookie from a query string (critical)

this endpoint takes a `suggest` parameter and writes it straight into `.ROBLOSECURITY`. that is how the 2016 client "negotiates" auth, except there is basically no extra check. whoever can hit that url can plant a session cookie.

abuse:
- if they already forged a jwt (see 1.1), they log themselves in as that user
- phishing pages can bounce someone through negotiate and lock in a session
- the ticket is in the url so proxies, browser history, and access logs eat cookies for breakfast

bubbablox still has this. it even marks the cookie HttpOnly, which is nice, except the damage already happened by putting the session in the query.

### 1.3 frontend cookie setter (`validate-and-add-cookie`) (high)

the 2016 next frontend has an api route that takes a cookie in the POST body and sets `.ROBLOSECURITY` on the browser. csrf is supposed to protect it. the csrf signing key is in `config.example.json` and a lot of people never change it.

abuse: if the csrf key is the example one, the "protection" is fake. an attacker can make a victim's browser accept a session the attacker chose, or more commonly just use it as another way to install a stolen/forged cookie.

### 1.4 bot password reset returns the new password (critical)

bubbablox has `GET botapi/resetpassword?userId=...`.

it checks a header (`BB-botAPIkey`) against `BotAuthorization`. then it resets that user's password to a random string and **returns the new password in the json**.

in original ecs, `BotAuthorization` is the same leaked string as everything else. DEBUG builds skip the check entirely.

abuse: pick a user id (owner is 1), hit the bot route with the known key, get a working password back. that is not "reset via discord dm". that is "the api tells you the password".

same family of routes:
- `botapi/discord/coinflip` spends/prints robux for a discord id
- `botapi/tickets/user/{discordId}` dumps user data tied to discord
- `botapi/migrate-alltypes` pulls assets from a url you choose (ssrf, see later)

### 1.5 place launcher falls back to user 1 (critical, bubbablox)

in bubbablox `PlaceLauncher.ashx`, if there is no ticket and no session, `userId` becomes `1`.

user 1 is the owner in basically every install guide.

abuse: join a game as the owner account. games that trust "the player who joined" now think the owner is in the server. combine with studio tools / place permissions / "this player is the creator so give them admin" scripts and it is over.

### 1.6 join tickets are the session cookie in the url (high)

bubbablox builds:

`/game/join.ashx?placeid=...&ticket=<the jwt>`

and `game/get-join-script` stuffs `.ROBLOSECURITY` into a place launcher url.

original ecs place launcher even puts the raw `.ROBLOSECURITY` cookie into the json as `authenticationTicket`.

abuse: anyone who can see that url (referrer leaks, discord, screenshots, rcc logs, "can you send the join link", web server access logs) has the account. this is how a lot of revival cookie logs happen without any fancy exploit. the site just hands the cookie to the client in a get url.

### 1.7 discord login / password reset cookies that are not HttpOnly (medium)

bubbablox sets `resetpasswordverified` with `HttpOnly = false`. some login cookies also use `SameSite = None`.

abuse: any xss on the site (forum, catalog description, chat, username if they render it raw) can read those flags and help finish a reset / session dance. HttpOnly false means javascript is in the cookie club.

### 1.8 DEBUG "make me an account" route (critical if debug)

original ecs, compiled in DEBUG:

`/integration-test/create-account-and-set-cookie`

creates a user with a hardcoded password, gives them builders club, auto-approves the application, and sets the session cookie.

`/game/get-join-script-debug` mints join tickets starting at user 12 (which the original readme treats as owner) and just increments.

abuse: if someone ships a debug build (people do this constantly), the site has a public "give me a staff account" button.

### 1.9 client integrity checks are turned off (high, bubbablox)

comments in the code literally say they know this is insecure.

- `GetAllowedSecurityKeys` returns `true`
- `GetAllowedMD5Hashes` returns a tiny hardcoded list and does not even require RCC like the original did
- `GetAllowedSecurityVersions` allows a couple old pcplayer versions

original ecs at least gated some of this behind `IsRcc()`. bubbablox made it worse.

abuse: modified clients, injectors, and patched exes do not get kicked. this is the green light for every 2016 executor script kiddie. they do not need a website 0day to ruin games. the website already said "yeah any client is fine".

---

## 2. printing money / ruining the economy

this is the part people actually care about on a revival called **economy** simulator.

### 2.1 free builders club (critical, bubbablox)

`POST buildersclub/membership` is a bypass route (skips csrf). if you are logged in you send a membership type and the server just does it.

it will:
- set your membership to BC / TBC / OBC
- give you the badges
- start the daily robux payout that membership is supposed to unlock

there is no payment check. no admin check. no "did they buy this".

abuse: every account becomes OBC. daily robux faucet. badges that are supposed to be rare become worthless. the economy is fake on day one.

### 2.2 marketplace purchase is on the csrf bypass list (high)

`marketplace/purchase` is `HttpPostBypass`. that means csrf middleware is told to ignore it.

it does try to read a session from `Roblox-Session-Id` or the cookie. so you still need to be logged in. but any other site can make your browser buy stuff while you are logged in, because csrf is off.

abuse: csrf an account into buying junk, draining robux, buying a shirt for max price, etc. not as sexy as free OBC, still wrecks wallets.

catalog purchase on the website side does use redis locks and a transaction, which is one of the few things they actually did right. the in-game marketplace path is the sloppy one.

### 2.3 game server "player left" pays tickets (high if gs auth is leaked)

when a fake or real game server reports a player leave, the backend pays tickets based on how many minutes they "played", capped but still farmable.

`GameServerAuthorization` in the original leak is the same public string as the bot key and the rcc key.

abuse: if that secret is known, you do not even need to play. you report joins and leaves and print tickets. tickets convert to robux on the currency exchange. that is a money printer with extra steps.

bubbablox also fires a discord webhook on join/leave with username and user id, so the same secret also becomes a live player tracker.

### 2.4 discord coinflip (high if bot key is leaked)

`botapi/discord/coinflip` bets robux 50/50. max 500, 25 a day, 4 second cooldown. uses `new Random()` which is not a casino rng.

abuse with the leaked bot key:
- flip on an account you do not own if you know their discord id
- grind expected value / rng until you are up
- drain someone else's balance by flipping them into the ground

it is also a GET, so it can end up in logs and prefetchers.

### 2.5 daily login / visit payouts (medium)

there are daily ticket grants, place visit payouts to creators, homestead/bricksmith badges at visit thresholds.

abuse: alt farms. visit bots. if gs auth is leaked this gets automated. even without that, 2016 clients plus no real rate limit on alts means the economy inflates until limiteds are a joke.

### 2.6 in-game purchases trust the client more than they should (medium)

game passes / products go through marketplace endpoints that the 2016 client calls. if a game developer did the classic "client says they bought it, give the gear" pattern (and they did, constantly, in 2016 places), exploiters do not need a website bug. they just fire the remote.

the website trying to be a 2016 recreation means you inherited every bad roblox game economy from 2016 on top of the site bugs.

---

## 3. taking over the actual server (rcc / rce / files)

this is the "they own the windows box" chapter.

### 3.1 RCC soap has no real auth (critical)

RCCService is the old roblox game server. you talk to it with SOAP: `OpenJob`, `OpenJobEx`, execute lua, load places.

ecs starts RCC and posts XML at `http://127.0.0.1:{port}`. if that port is bound to `0.0.0.0` or forwarded, or if another process on the box can reach it, there is usually no user login. whoever can speak SOAP can make RCC run lua.

bubbablox example config binds the website to `http://0.0.0.0:80`. people then port-forward RCC "so games work".

abuse:
- run arbitrary lua as the game server
- dump DataStores, player chats, memory
- load a malicious place
- use the server as a free proxy (HttpService gets enabled in a bunch of scripts)
- in the worst case, break out via whatever native bugs that 2016/2018 rcc still has

this is why "do not expose rcc" is revival gospel and why people still do it anyway.

### 3.2 RCC access key stuffed into lua and asset urls (high)

game server templates put `apiKey` in the lua, and place fetch urls look like:

`/asset/?id={placeId}&apiKey={RccAuthorization}`

if you have the original leak, you already have the default key. if you do not, the key still shows up in:
- rcc logs
- join/load scripts
- error messages
- anybody who can read the DataModel / server script source (studio, leaked place, misconfigured replication)

abuse: once you have the rcc key you can hit asset delivery as "the renderer", skip 18+ checks, skip moderation checks, and talk to datastore endpoints that only check `accesskey`.

### 3.3 QuietGet path traversal (critical on original ecs)

original:

`Setting/QuietGet/{type}` does `Path.Combine(jsonDir, type + ".json")` with no allow list.

bubbablox added an allow list. original did not.

abuse: walk out of the json folder and read other files the process can read. depending on the install path that can mean configs, more secrets, maybe source. classic "the client settings endpoint is a file reader".

### 3.4 migrate-alltypes SSRF (high)

`botapi/migrate-alltypes?url=...` fetches a url and imports it as a roblox asset (images, audio, meshes, lua, models, animations, the lot).

auth is the bot key, which is leaked / skipped in DEBUG.

abuse:
- point it at internal urls (`http://127.0.0.1:...`) and use the site as a proxy
- pull a malicious rbxm/lua and get it stored as an asset the game servers will load
- hit cloud metadata if they hosted this on a real vps

### 3.5 asset endpoint proxies to real roblox (medium-high)

if the asset is not in the local db, bubbablox fetches `{AssetUrl}/asset/?id=...` (example points at some random host) and then caches the bytes.

abuse:
- bandwidth / disk bomb (make it cache huge junk)
- SSRF-ish depending on what AssetUrl is set to
- sneak unreviewed roblox assets onto the revival
- if AssetUrl is attacker controlled in a bad config, you are loading attacker files into games

there is also a header `RbxTempBypassFor18PlusAssets` that the comments say to remove. it marks you as 18+ with no account. so age gated content is a header away.

### 3.6 asset validation service has no auth (medium)

`AssetValidationServiceV2` is a fiber app. `/api/v1/validate-place` and `/api/v1/validate-item` take a raw body and parse it. no key.

abuse: if the port is public, anyone can DOS the validator with giant places. also the validator is not a sandbox. a crafted file that blows up the parser is a bad time. it is supposed to stop malicious places. it is also a free unauthenticated parser on the network.

### 3.7 Process.Start in admin / web (medium, needs staff)

admin api and some internal web endpoints start processes (rbxmk, obj conversion, rcc). if those arguments ever take user paths/names without care, that becomes command injection. i did not write a full follow of every argument. treat any "staff tool that shells out" as hostile until proven otherwise.

### 3.8 UnsecuredContent is literally in the allow list (low-medium)

the site serves a folder called `UnsecuredContent` on purpose, and the application guard allows it with no login.

abuse: depends what files a host dumped in there. people put clients, places, keys, logs, "temp" zips. the name is the warning.

---

## 4. wrecking games (the client side everyone already knows)

even if the website was perfect, 2016 roblox is not.

### 4.1 filtering enabled is optional, and lots of places never turned it on

2016 is the FE transition era. tons of ecs places are FilterType 0 / FilteringEnabled false because they were saved that way.

abuse (in-game, not a website 0day):
- local scripts replicate to the server
- exploiters spawn parts, give themselves tools, set their walkspeed, change leaderstats if those are not protected
- remotes that do `GiveMoney.OnServerEvent:Connect(function(player, amount)` get fired with 999999999
- classic "dex explorer" stuff

this is how 90% of "i got free admin in a game on ecs" happens. the website did not even need to be involved.

### 4.2 HttpService gets turned ON in renderer / thumbnail / some game scripts

renderer lua sets `HttpService.HttpEnabled = true`. bubbablox GameServer.lua also forces http on in a few paths and has a **hardcoded discord webhook** in the script.

abuse:
- games can phone home
- a malicious place can exfiltrate player names, ips the server can see, and whatever the webhook is supposed to get
- that webhook in GameServer.lua is a live secret in source. anyone with the repo can spam it, delete it if they have control, or just watch join traffic if the hook is still valid
- webhooks in client javascript (a classic ecs fork move) means every visitor can read the url in view-source and dump whatever the site was logging, including logins if some idiot logged passwords to discord (a lot of people did)

### 4.3 FFlagServerScriptProtection is false in shipped client settings

server script protection off means the client/rcc combo is more willing to run sketchy scripts. combined with loadstring flags being "hidden" instead of actually disabled, you get the usual 2016 script executor playground.

### 4.4 chat filter is fake (high for a kids-adjacent 2016 recreation)

bubbablox `Game/ChatFilter.ashx` returns `"Hi gu"` for both white and black lists. the v1/v2 moderation filter endpoints echo the text back unchanged. comments say "add a real filter eventually".

original ecs also just echoes the input.

abuse:
- unfiltered chat in game and on some website surfaces
- if any page renders chat/comments as html, that becomes xss
- this is also just a legal / safety nightmare if minors are on the site, which they will be, because it looks like 2016 roblox

### 4.5 studio login is a second copy of login with extra parsing (medium)

`v2/login` for studio is another bypass route. it has a rate limit, good. it also has a bunch of body parsing branches for studio vs website. more code paths = more chances a check gets skipped.

---

## 5. data leaks, xss, csrf, and "the website part"

### 5.1 HttpGetBypass / HttpPostBypass (this is the original sin)

they made custom attributes that register the route on three skip lists at once:
- frontend proxy bypass
- application guard allow list
- **csrf bypass list**

tons of state-changing routes are on it: login, purchase, membership, datastores, badge award, gs shutdown, bot apis, asset GET/POST.

csrf exists on paper. then they labeled half the site "bypass".

abuse: cross site requests from a malicious page while you are logged in. buy, friend, follow, change settings, depending on the route. get routes that change state are extra cursed because browsers will follow them from an image tag.

### 5.2 persistence/getv2 fetches data before it checks RCC (medium)

it reads datastore keys, prints them to the server console, then checks `IsRcc()` and errors if you are not rcc.

abuse: maybe you still get a 400. the data already hit the logs. if you can trigger it, you pollute logs with secrets and you get a timing/error oracle. do not log datastore values. ever.

datastore set/get are supposed to be rcc-only. if the rcc key leaks (it will), the whole DataStore is attacker-controlled. that is every tycoon save, every inventory, every "server sided" currency that was actually in a datastore.

### 5.3 open redirect to roproxy (low-medium)

if product info is missing, bubbablox redirects to `https://economy.roproxy.com/v2/assets/{id}/details`.

abuse: not a full open redirect. it does send your players at a third party proxy. that proxy sees ips and can serve junk. also it teaches the client that "missing asset? follow this other host".

### 5.4 AllowedHosts * and captcha test keys (medium)

example configs:
- `AllowedHosts: *`
- hCaptcha public/private are the official test keys that always pass
- postgres password in the original json is a real looking secret, not a placeholder
- twitter api keys in the original json are real looking secrets
- `OwnerUserId` is 1, or a list including 1, 12, 16, 74

abuse: skip captcha, brute force signups, first account is owner, host header weirdness, and anyone who cloned the repo has the original operators' keys (those twitter keys should be treated as burned).

### 5.5 IP addresses

the site sends player ips to iphub. game servers see player ips. hosts of games see player ips. join scripts in original ecs even hardcoded a machine address.

abuse: doxxing, swatting adjacent harassment, IP bans that are easy to bypass, and "the owner of the game can see who joined from where". revival communities have been warning about this for years. vpn or do not play.

### 5.6 xss in user content (likely, treat as real)

2016 frontend is react, which helps, but there are still old aspx-style pages, admin bundles, jquery, and places where descriptions/usernames/forum posts get dumped. i did not exhaust every render path. assume forum + catalog descriptions + shout + discord names are xss until someone proves they encode.

abuse: xss on a revival is cookie city, especially with negotiate.ashx and validate-and-add-cookie sitting there. steal sessions, force purchases, plant a fake login page, hook the csrf token.

### 5.7 bbmons login codes use `new Random()` (low-medium)

`bbmons/login` makes a 32 char code with System.Random and redirects to `https://bbmons.org/login/callback?code=...`.

DEBUG skips the api key check on the redeem side.

abuse: if the sister site is still a thing, weak rng plus no binding to the destination origin is a "login as this user on the other game" problem.

### 5.8 badge award is rcc-gated, but rcc is spoofable (medium)

awarding a badge checks `accesskey == RccAuthorization`. good idea. the key is in the lua and in the example config.

abuse: with the key you award any badge that is associated with a place. badge hunting, fake prestige, whatever games use badges as keys.

### 5.9 18+ and moderation skip for "bots" (medium)

bot-auth header matching BotAuthorization disables encryption and 18+ / moderation gates on assets.

abuse: leaked bot key means you download unapproved and 18+ assets. some hosts store stuff they should not. this is how that stuff walks out.

---

## 6. secrets people keep leaving in the tree

this is its own category because it keeps happening.

| what | why it matters |
| --- | --- |
| jwt session key | forge `.ROBLOSECURITY` |
| BotAuthorization | reset passwords, coinflip, migrate assets, dump discord links |
| RccAuthorization | pretend to be the game server, read/write datastores, grab gated assets |
| GameServerAuthorization | fake player joins/leaves, shutdown servers, farm tickets |
| discord webhook in GameServer.lua | spy on joins, nuke the webhook, spam |
| discord webhooks in frontend js | anyone can view-source the "secret" logger |
| postgres password in appsettings.json | the database is the whole game |
| twitter keys | those accounts are burned |
| hcaptcha test keys | bots sign up forever |
| RSA private keys used to sign join scripts | if the pem files shipped with a host's deploy, you can forge join scripts and sit in games as whoever |
| csrfKey in frontend config.example | forge frontend csrf |
| IPHub api key | billed abuse / ip intel |

original ecs used ONE string for authorization, game server auth, bot auth, and rcc auth. that is not four locks. that is one lock with four doors.

---

## 7. how this stuff actually gets abused in the wild (no steps, just the movie)

this is the "what it looks like when it goes wrong" section so you can recognize it.

**the cookie log revival.** host copies ecs, leaves jwt or bot key default. someone mints owner cookie or hits resetpassword. they add a discord webhook to login. next 200 signups get their passwords mailed to a discord channel. that is why the community says never reuse a real password or email on a revival.

**the economy is dead in a week.** someone finds free OBC, or gs auth, or a remote in the main game that adds cash. they dump limiteds, crash the ticket exchange, and flex on the discord. host rolls back the db or does not.

**the "executor works here" clip.** client md5 checks are off, FE is off on the main game, HttpService is on. someone runs a 2016 script hub, becomes admin in every server, crash loops the rcc, host blames "hackers" instead of FilterType.

**the rcc is on the internet.** someone scans the soap port, OpenJobs a lua payload, the windows box starts mining or the places all get overwritten. host reformats.

**the "security patcher".** some of these forks add a patcher that "fixes webhooks" and then quietly logs usernames and passwords to another server. if a login form is sending your password anywhere besides the login api, that is not a patch. that is a steal.

**csrf from a cool html page.** because so many money routes are bypass, a fake catalog page on another origin can click buy for you.

**owner joined your private place.** place launcher defaulted to user id 1, or someone forged a ticket, and now "the owner" is in a 13+ place they should not be in / is grabbing uncopylocked source.

---

## 8. what is actually ok-ish

credit where it is due so this does not sound like "everything is doomed" copium.

- website catalog purchase uses a redis lock plus a db transaction and re-checks balance. that part is trying.
- a lot of cookies are HttpOnly + Secure + SameSite Lax when they remember to set it.
- bubbablox added an allow list on QuietGet. original did not. keep that.
- badge award and some datastore writes check an rcc key. the problem is the key handling, not the idea.
- studio login has a rate limit.
- staff filter exists and owner is explicit. the problem is becoming the owner, not the filter class.

none of that saves you if jwt is `hello world 12345`.

---

## 9. fix this first if you are dumb enough to host it

not a full harden guide. just the order that stops the bleeding.

1. **rotate every secret.** jwt, bot, rcc, gs, postgres, discord, csrf. assume the example values are public forever.
2. **do not bind rcc or redis or postgres to the internet.** website reverse proxy only.
3. **delete negotiate-from-query and cookie-in-url.** session stays in a cookie. join tickets should be short lived, single use, and not be the session jwt.
4. **delete free membership.** membership is a paid/admin action or it is fake.
5. **csrf bypass list should be tiny.** login maybe. purchase no. bot no. gs no.
6. **bot routes should not return passwords.** ever. and DEBUG must not skip auth in anything you compile for prod.
7. **place launcher must refuse anonymous joins.** no user id 1 fallback.
8. **turn client integrity back on** or just accept that every game is pwned.
9. **strip webhooks out of lua and javascript.** webhooks are server-only or they are public.
10. **force FilteringEnabled on for every place** you did not personally audit. 2016 games will break. that is cheaper than the alternative.
11. **real chat filter or disable chat.**
12. **do not ship DEBUG.**
13. **captcha keys have to be real.**
14. **first registered user should not automatically be god** without a setup token you already have.

if you skip 1, you can skip the rest, because someone already has admin.

---

## 10. severity cheat sheet

critical (site or economy is gone):
- default/leaked jwt
- default/leaked bot key + resetpassword
- negotiate.ashx cookie plant
- place launcher = user 1
- free OBC
- rcc soap exposed
- quietget path traversal (original)
- debug account factory left on

high:
- session jwt in join urls
- csrf bypass on money
- client hash checks disabled
- gs auth leaked -> ticket printer
- hardcoded webhooks
- migrate ssrf
- fake chat filter
- 18+ header bypass
- frontend csrf example key

medium:
- asset proxy
- captcha test keys
- AllowedHosts *
- datastore log-then-auth
- SameSite None / HttpOnly false
- IP exposure
- unauthenticated validator
- FE-off places
- xss in user content (until proven encoded)

low but still annoying:
- roproxy redirect
- UnsecuredContent
- telemetry endpoints that just return ok (info about the stack)
- comments in source that say "remember to remove this bypass"

---

## 11. final honesty paragraph

economy simulator / bubbablox is not "a couple cves". it is a 2016 client, an unauthenticated game server, a website that labeled its csrf skip button `HttpGetBypass`, and a readme that tells you to make user 1 the owner.

people keep hosting it because it looks like old roblox and the source is right there. then they are surprised when the limiteds are gone, the discord is full of cookies, and rcc is mining.

if you play on one of these: unique password, throwaway email, vpn, do not download random clients, do not paste cookies, do not click "login with discord" unless you trust the host with that discord.

if you host one of these: rotate secrets, then assume you already got popped before you rotated them.

that is the rundown.

---

## auto tools (audit + patcher trust)

read-only scanner (linux / windows, python 3):

```bash
python3 /opt/ecs-security-patcher/ecs-audit.py --source /path/to/ecs --url https://your.domain --json report.json
python3 /opt/ecs-security-patcher/ecs-audit.py --source /path/to/ecs --trust-only
```

mirror + docs: `tools/ecs-security/README.md`, patcher transparency: `/opt/ecs-security-patcher/TRUST.md` and `patch-transparency.json` after `--apply`.
