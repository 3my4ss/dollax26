# dollax26
Cloudflare Worker Dollax26 Panel — full build

Files

File	Purpose
worker.js	The complete Worker script. Deploy this.
preview.html	Standalone UI preview with mock data (open in a browser).
README.md	This document.
Supporting sources: base.js (your original), tpl_dashboard.txt, tpl_subpage.txt, build.js, build2.js (build pipeline), test.js, migrate-test.js, check.js, mock.js, make_preview.js.

What changed vs. your original
1. Appearance — Settings → Appearance
Language English / فارسی — instant switch, full RTL for Farsi, saved in D1 (app_settings.language). Quick toggle pill in the top bar too.
Interface style Solid / Glass (frosted, translucent panels).
Theme 7 swatches: Dark Green (default), Dark Cyan, Dark Blue, Green, Cyan, Blue, Orange.
Theme/style/language persist in D1 and are cached in localStorage for instant paint.
2. Clients — per-client options
Traffic limit (GB) (enforced at the relay), Expiration, Maximum IPs.
Ports — restrict which ports a client may use (all = every port).
Clean IPs — restrict which clean IPs appear in that client’s configs (all = every clean IP).
3. Correct symbols / UTF-8
Removed all mojibake → proper ∞ · × — and clean nav glyphs; duplicate broken CSS removed.
4. Client connection — modelled on yonggekkk/Cloudflare-vless-trojan
This is the part that decides how VPN clients connect to the clean IPs / ports / protocols.

Early data (0-RTT): generated links now use a ?ed=2560 path suffix, and the relay decodes the WebSocket Sec-WebSocket-Protocol header (decodeEarlyData) so the first packet rides in the handshake — matching how yonggekkk’s clients connect.
Full 13-port matrix: Settings → Connection → Port range = All 13 CF ports makes the panel emit nodes for every Cloudflare edge port — 80, 8080, 8880, 2052, 2082, 2086, 2095 (no TLS) and 443, 8443, 2053, 2083, 2087, 2096 (TLS) — across your clean IPs, exactly like the yonggekkk subscription. Switch to Inbound ports only for the old behaviour.
ProxyIP fallback (now per-inbound): each inbound has its own ProxyIP field (Inbounds → Add/Edit). When a direct TCP connection to the destination fails (typical for CF-hosted sites like X / ChatGPT), the relay retries once through that inbound’s ProxyIP. Still overridable per-connection with &pyip=<ip[:port]>. Empty = no fallback.
Subscriptions in the yonggekkk formats for every client:
/sub/<token>/cl — Clash-meta YAML (proxies + PROXY/AUTO groups + rules)
/sub/<token>/sb — sing-box JSON (outbounds + selector + urltest)
/sub/<token>/ty (alias /raw) — generic base64 v2ray list
/sub/<token> — human-readable HTML page (now with Clash/sing-box buttons)
/pcl, /psb, /pty aliases also accepted.
Protocols covered per node: VLESS, VMess, Trojan, Shadowsocks (the panel’s inbounds), with ws transport, Host/SNI = your worker host, address = clean IP.
5. Backend
clients gains ports_json, clean_ips_json; app_settings gains theme, ui_style, language, proxy_ip, port_matrix (all auto-migrated).
New/changed endpoints: /api/settings (GET/POST extended), /api/clients (POST/PATCH accept ports+cleanIps), /sub/<token>/{cl,sb,ty,raw,pcl,psb,pty}.
6. Cleanup & three working inbounds (this round)
Inbounds: exactly three are seeded — VLESS Edge, VMess Edge, Trojan Edge. VLESS and Trojan are handled natively by the Worker. The legacy default Shadowsocks Edge inbound is removed when unused.
Outbounds: only a single working DIRECT entry is seeded. The old empty GERMANY SOCKS5 default (which never worked) is deleted automatically, and anything pointing at it — or with no outbound set — is repointed to DIRECT. No broken/needless outbounds remain.
HTTP CONNECT outbound is now actually implemented (it was selectable but returned “Unsupported outbound”). SOCKS5, DIRECT, BLOCK and HTTP all work.
Removed dead code (endpointList, endpoints, getSettingSyncFallback) and dropped the prefilled username on the login screen.
The Inbounds page now says plainly which protocols are native and which need the bridge.
VMess honesty note: no mainstream Cloudflare-Worker panel (yonggekkk, cmliu, BPB) implements VMess natively — it requires AES-ECB/AES-GCM crypto that Workers don’t fully expose and that no reference handles. VMess therefore runs through the Xray WebSocket bridge: set Settings → Xray bridge to your Xray server (the panel’s /api/xray/export generates the matching server config). Until then use the VLESS or Trojan inbound, which work out of the box.

7. Panel speed, admin scoping, client clean-IP picker (this round)
Less lag:
initDB now has a schema-version fast path — on a warm deployment it does a single read instead of re-running ~30 migration queries on every cold start.
The dashboard now loads everything through one GET /api/bootstrap call instead of five parallel requests (inbounds+outbounds+clients+clean-IPs+settings).
Admin permissions are enforced in the UI, not just the API. GET /api/me returns the admin’s role + permissions; the sidebar only renders the sections that admin is allowed to open (pageAllowed/PAGE_PERMS), and the router redirects anything else to Overview. The API was already scoped, so together a limited admin sees only their exact sections. Mapping: Inbounds→create/edit/deleteInbound, Outbounds→manageOutbounds, Clients→create/edit/deleteClient, Admins→manageAdmins, Clean IPs→manageCleanIPs, Settings→manageSettings, Logs→viewLogs; Overview is always visible.
Client clean-IP picker: the Add-Client form now starts with no clean IPs selected, with an All button to tick them all. Selection is stored explicitly — none selected = the Worker host only (no clean IP). The client table shows Worker only when empty.
8. Appearance is now draft + Save (this round)
In Settings → Appearance, choosing language / interface style / theme only updates the selection and shows a red “Unsaved changes” note — nothing on the panel changes yet.
A Save appearance button commits it: it applies the new language/style/theme and persists the choice to D1. Until you press Save, the panel keeps its current look.
Opening Settings always starts the draft from the currently-saved values (so nothing stale leaks in), and the top-bar language pill remains a quick instant toggle.
9. ProxyIP moved into Inbounds (this round)
The ProxyIP field was removed from Settings → Connection (that panel now only holds the port range).
ProxyIP is now per-inbound — Inbounds → Add/Edit has its own ProxyIP field, and the Inbounds table has a ProxyIP column.
The four default inbounds each ship a different public ProxyIP: VLESS pyip.ygkkk.dpdns.org (yonggekkk) · VMess proxyip.cmliussss.net · Trojan proxyip.us.fxxk.dedyn.io · Shadowsocks proxyip.hk.fxxk.dedyn.io.
New inbounds you create start with an empty ProxyIP (no fallback) until you set one.
The relay now uses that inbound’s ProxyIP, so different inbounds can exit through different relays. The per-connection &pyip= override still works.
10. Config clarity + workers.dev ports (this round)
Every node name now shows its endpoint — e.g. Alice VLESS Edge 104.16.0.1:443 TLS — so you can tell at a glance which address/port/protocol each node uses (same for the VMess ps field). Previously every node was just name + inbound, which is why configs looked like they had “no clear address”.
*.workers.dev only serves ports 80 and 443. When a node points at the workers.dev host, the panel now drops the other 11 ports automatically so configs never contain nodes that can’t connect. Nodes that point at a clean IP still get the full port set. For all 13 ports, use a custom domain.
Confirmed the tunnel itself is fine: a simulated VLESS client received the [version,0] response header plus the real destination payload.
11. UDP / DNS support (this round) — fixes “ping works but nothing loads”
The relay previously rejected all UDP, so in TUN-mode clients (sing-box/v2rayN) DNS lookups died: TCP ping to the node succeeded and traffic was counted, but no page would load.
VLESS UDP is now supported for DNS (port 53), resolved through DNS-over-HTTPS (cloudflare-dns.com/dns-query) — the same approach yonggekkk/edtunnel use, since Workers have no raw UDP sockets. Other UDP ports are still rejected (as on every CF Worker).
Verified in the relay simulator: a VLESS UDP(DNS) request produced a DoH call and the client received [version,0][length][answer].
12. Default login (this round)
Default owner credentials are now dollax26 / dollax26.
Because the seed only applied on an empty admins table, a locked-out owner was stuck. There is now a one-time forced reset (owner_reset_v1) that sets the owner back to dollax26 / dollax26 once on the first run after deploying this build — then never again, so a password you change afterwards is safe.
Verified: 46/46 functional tests (login with the new password) and 13/13 migration tests (a pre-existing admin row is reset to dollax26/dollax26, role owner, enabled).
13. Corner style + custom fonts (this round)
Settings → Appearance gained two controls (both part of the draft-then-Save flow):
Corner style: Rounded (default) ↔ Cubic (square corners) — stored in app_settings.corners, applied via html[data-corners=...].
Font: Default plus three per language — English Allpony / Triakis / Incorrigible, Farsi Sheed / Kamran / Vesterbro — stored in app_settings.font_en / font_fa, applied via html[data-font=...]; the active set follows the selected language.
The six fonts are embedded as base64 @font-face data URIs in the dashboard (no extra binding or storage) by make_fonts.js → tpl_fonts.txt, spliced in by build.js. Worker grew to ~893 KB (still well under the Workers script limit).
New settings keys are validated server-side (corners ∈ {round,square}, font keys ∈ fixed sets).
14. Self-service account for every admin (this round)
Settings is now reachable by every logged-in admin, and its first panel is My account: the logged-in admin’s own username (read-only) plus their display name and their own password (current + new).
New endpoint POST /api/me/password (login required, no extra permission): verifies the current password, then updates that user’s hash/display name. The other Settings sections (Panel Settings, Xray bridge, Connection, Appearance) still require manageSettings.
GET /api/settings and /api/bootstrap now report the current user’s name, instead of always showing the first/owner admin.
Deploy
Cloudflare → Workers & Pages → your Worker → Edit code → paste worker.js → Deploy (or wrangler deploy).
Keep the same D1 binding IOT_DB. Migration is automatic on the first request.
Open /dashboard → Settings → Appearance (language/style/theme) and Settings → Connection (ProxyIP, port range). Set a new owner password.
Verification
node --check on worker.js → ESM syntax OK; embedded dashboard script compiles.
54/54 functional tests (in-memory SQLite D1 stand-in): init, login, settings defaults & persistence, dashboard, clean IPs, four protocol inbounds with distinct ProxyIPs, new inbound ProxyIP empty, inbound ProxyIP saved, outbounds cleaned to a single working DIRECT, client create, per-client ports/clean-IPs, no-clean-IP → worker host, workers.dev config limited to 80/443, node name shows endpoint, UDP DNS via DoH, node generation honouring selections, VLESS link shape, early-data decode, 13-port matrix, ed=2560 in links, Clash / sing-box / generic subscriptions, single /api/bootstrap, admin permission scoping, appearance draft + Save, corner style + embedded fonts, self-service password change (wrong-password rejected, new password works, settings shows the logged-in user), localized subscription, 404s.
13/13 migration tests: an existing DB gains the new columns/settings with no data loss, the default inbounds get their distinct ProxyIPs backfilled, a locked-out owner is reset to dollax26/dollax26, the broken empty SOCKS5 outbound is removed, and legacy rows are repointed to DIRECT.
Run: node test.js · node migrate-test.js.
Notes
ProxyIP is a fallback — direct connections are tried first, so setting it does not slow normal traffic.
Clash has no Trojan-over-WS-without-TLS proxy type, so non-TLS Trojan nodes are omitted from the Clash subscription only (they remain in the generic and sing-box subscriptions).
preview.html uses mock data; write actions in it do not persist.
Troubleshooting: “upload works but no download”
Symptom: the client shows upload traffic, the connection appears to open, but nothing comes back (DNS inside the tunnel times out, pages never load).

Two causes, both addressed:

Relay handshake handling (fixed). The old relay sent the VLESS response header as its own frame and only retried on a thrown error. It now:

buffers the handshake until the header is complete,
prepends the 2-byte VLESS response header to the first data chunk (the pattern v2rayNG / sing-box / Clash expect),
guards every send on readyState,
and, if the remote socket yields no data at all, retries once through the configured ProxyIP (any non-block outbound).
Cloudflare-hosted destinations need a ProxyIP. A Worker cannot open a direct TCP connection to a site that is itself behind Cloudflare (X, ChatGPT, many CDNs) — the connection opens but no data returns, which looks exactly like “upload only”. Fix: Settings → Connection → ProxyIP = a relay host (ip:port or domain, default port 443). You can also override it per link with ...?ed=2560&pyip=1.2.3.4:443.

Also check the outbound your inbound uses (Outbounds page): the default GERMANY SOCKS5 entry has no host until you fill it in — an unreachable SOCKS5 server will break the tunnel. Use DIRECT for the simplest setup, or a working SOCKS5, and set a ProxyIP for CF-hosted targets.

After changing connection settings, reload the client subscription so it re-reads the links.
