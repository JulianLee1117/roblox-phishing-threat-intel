# Roblox Phishing Threat Brief

*February 2026*
*Prepared as part of independent security research*

---

## Executive Summary

Roblox's 151M+ daily active users -- over half under 13 -- face a diverse phishing ecosystem spanning credential harvesting, malware distribution, CPA fraud, and Discord OAuth token theft. This brief documents findings from a collection of 1,999 phishing URLs across 7 threat intelligence sources, followed by deep infrastructure and content analysis of 5 live domains representing 4 distinct attack categories. The key finding is that the phishing supply chain is modular: attackers assemble attacks from independent services (Eggywall for reverse proxy infrastructure, Vaultcord for Discord OAuth theft, XF Content Locker for CPA monetization, Storbix for site templates) rather than building monolithic phishing kits. None of the 5 analyzed domains used .ROBLOSECURITY cookie theft -- but that complementary vector is the one Roblox is actively hardening against with a cookie format change scheduled for May 1, 2026.

---

## Methodology

### Collection

A Python pipeline (`collect.py`) queried 7 threat intelligence sources and deduplicated results:

| Source | URLs | % of Total |
|--------|-----:|----------:|
| GitHub: Phishing.Database | 1,669 | 83.5% |
| crt.sh (Certificate Transparency) | 186 | 9.3% |
| urlscan.io | 83 | 4.2% |
| OpenPhish | 26 | 1.3% |
| GitHub: Phishing.Army | 23 | 1.2% |
| PhishTank | 8 | 0.4% |
| GitHub: phishing-filter | 7 | 0.4% |
| DevForum + Roblox Wiki (manual) | 5 | 0.3% |
| **Total (deduplicated)** | **1,999** | |

84% of URLs came from a single blocklist (Phishing.Database). This data skew motivated a pivot from broad collection to deep analysis of representative domains.

### Analysis approach

- **Target selection:** 5 live domains chosen across 4 attack categories for diversity (credential harvesting, malware distribution, CPA fraud, Discord OAuth theft)
- **Infrastructure recon (Phase 1):** DNS (A/AAAA/NS/MX/TXT), WHOIS, HTTP headers, TLS certificate details, Certificate Transparency history (crt.sh), IP geolocation and ASN (ipinfo.io), reverse DNS, urlscan.io scan data
- **Content analysis (Phase 2):** HTML source and urlscan DOM snapshots analyzed for credential harvesting forms, exfiltration endpoints, JavaScript behavior, anti-analysis techniques, social engineering signals, and phishing kit indicators
- **Ethical constraints:** Passive observation only -- no credentials submitted, no forms interacted with, no malware downloaded. All analysis used publicly available data (DNS, WHOIS, HTTP headers, HTML source, Certificate Transparency logs, urlscan.io cached data).

---

## Dataset Overview

### Category breakdown

| Category | Count | % |
|----------|------:|----:|
| ccTLD abuse (roblox.com under foreign TLDs) | 1,348 | 67.4% |
| Typosquatting (character mods, prefixes, hyphens) | 564 | 28.2% |
| Other (GitHub Pages, misc) | 81 | 4.1% |
| Malware download | 4 | 0.2% |
| URL shortener | 2 | 0.1% |

### Notable patterns

- **.com.kz concentration:** 426 domains (21.3%) use Kazakhstan's .com.kz ccTLD -- a single registrar or infrastructure may be behind this cluster
- **Profile link lures dominate:** 1,514 URLs (75.7%) mimic `/users/ID/profile` paths -- the most natural link to share in Roblox social contexts
- **Private server lures:** 114 URLs (5.7%) exploit the `?privateServerLinkCode=` parameter pattern
- **89.5% dead:** 1,789 URLs are no longer active. 82 confirmed active, 62 possibly active (behind WAF), 65 with SSL errors
- **420 unique domains** across 1,999 URLs
- **Platform-hosted:** Vercel (2), Netlify (2), GitHub Pages (2) -- free-tier abuse is common but not dominant

---

## Domain Teardowns

### 1. roblox-com.pl -- ccTLD Login Clone

**Category:** Credential harvesting via pixel-perfect Roblox login clone

| Attribute | Value |
|-----------|-------|
| Hosting | GitHub Pages (Fastly CDN, 185.199.108-111.153) |
| Registrar | OVH SAS (France) |
| TLS | Let's Encrypt R13 (renewed Jan 19, 2026) |
| Created | 2025-11-04 |
| Status at analysis | **404 (content removed, infrastructure intact)** |

**Attack mechanics:**
- Pixel-perfect Roblox `/login` page clone with **28 locally-hosted CSS files** scraped from real roblox.com (SHA-256 content-hash filenames indicate automated scraping)
- Three credential harvesting vectors: "Log In" button submits the form directly; "Email Me a One-Time Code" and "Use Another Device" buttons both dispatch submit events on the same form via `onclick` handlers -- every button the user clicks harvests credentials
- Exfiltration script `css/oefdspofrewoisfewfewfw02349.js` uses **directory masquerading** (JavaScript file placed in `css/` directory to blend in with 28 legitimate CSS files) with a keyboard-mashed filename to evade signature detection
- Decorative FunCaptcha loaded from legitimate `roblox-api.arkoselabs.com` with an empty callback (`function reportFunCaptchaLoaded() {}`) -- creates the appearance of bot protection without functionality
- CSRF token meta tag copied from real Roblox (`data-token='Kmz/DzjdHDnh'`) -- non-functional on static phishing page but adds fidelity

**Notable findings:**
- **Polish-speaking operator:** HTML comments `<!-- CSS Roblox – zachowane dla wyglądu -->` ("kept for appearance") and `<!-- FunCaptcha (opcjonalny) -->` ("optional")
- **CT logs link to sibling domain:** A January 2023 certificate for `roblox-com.us` included `roblox-com.pl` as a SAN, proving the same operator runs parallel ccTLD phishing campaigns
- **Two-phase operation:** CT logs show Jan-Feb 2023 activity (ZeroSSL + Let's Encrypt certs), then ~2.5 year dormancy, then reactivation Nov 2025 with new WHOIS registration
- **Incomplete takedown:** Content removed (likely via GitHub abuse report) but domain registration (valid until Nov 2026), TLS cert (renewed Jan 2026, valid until Apr 2026), DNS, MX records, and SPF all remain active. Redeployable in minutes.
- **Copyright frozen at 2022** -- timestamps when the phishing kit's assets were originally scraped from roblox.com

**Security concepts:** Credential harvesting, directory masquerading, CSRF token mimicry, takedown effectiveness (content removed but infrastructure intact), Certificate Transparency as OSINT, zero-cost attack infrastructure ($5/year domain + free GitHub Pages + free Let's Encrypt)

---

### 2. www-roblox-com-frr-users-6048717178.vercel.app -- Platform-Hosted French Credential Harvester

**Category:** Credential harvesting with dual Discord webhook exfiltration

| Attribute | Value |
|-----------|-------|
| Hosting | Vercel free tier (Amazon AS16509 anycast) |
| TLS | Google Trust Services wildcard (`*.vercel.app`) |
| WHOIS | N/A (Vercel subdomain) |
| Status at analysis | **Live (200 OK)** |

**Attack mechanics:**
- French-language Roblox login clone ("Connexion a Roblox") with `username` and `password` fields
- **Dual Discord webhook exfiltration** to webhook ID `1408202683021529099`:
  1. **Passive visitor beacon** (`sendVisitInfo()`) fires on every page load via `DOMContentLoaded` -- the attacker gets IP + user-agent + URL for every visitor, even those who never submit the form
  2. **Credential theft** (`sendToWebhook()`) fires on form submission -- sends username, password, victim IP, user-agent, and timestamp as a formatted Discord embed
- **IP harvesting** via `api.ipify.org` -- fetches victim's real public IP on page load (necessary because Vercel CDN logs are inaccessible to the attacker)
- Roblox logo loaded from Wikimedia Commons (`upload.wikimedia.org`) -- avoids requests to Roblox CDN that could be detected
- On successful exfiltration: redirects to real `https://roblox.com/home` (the authenticated landing page) -- victim thinks the login worked
- On webhook failure: shows fake error "Erreur mot de passe/username incorrect !." -- encourages retries with different credentials

**7 anti-analysis techniques:**

| # | Technique | Implementation |
|---|-----------|---------------|
| 1 | Right-click disabled | `contextmenu` event with `preventDefault()` |
| 2 | Keyboard shortcuts blocked | F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U, Ctrl+Shift+C, Ctrl+S all intercepted |
| 3 | DevTools size detection | `setInterval` at 500ms comparing `outerHeight-innerHeight` > 160px; redirects to google.com |
| 4 | Debugger timing oracle | `debugger;` statement with timing check -- if paused > 100ms, debugger is attached; redirects to google.com |
| 5 | Text selection disabled | CSS `user-select: none` + `selectstart` event listener |
| 6 | Drag-and-drop disabled | `dragstart` event with `preventDefault()` |
| 7 | Console warning | Large red "ARRET !" (STOP!) message styled to mimic bank/social media DevTools warnings |

**Notable findings:**
- **Zero obfuscation** -- all JavaScript is plaintext with French comments. The attacker relied on volume over stealth.
- **"Learning site" label** -- Discord embed footer reads "Site d'apprentissage - Donnees completes" ("Learning site - Complete data"), suggesting a tutorial-following deployment
- **Webhook token fully exposed** in plaintext -- anyone viewing the source can send messages to the attacker's Discord channel, retrieve recent messages, or delete the webhook
- **Single point of failure** -- both visitor tracking and credential theft use the same webhook; if Discord disables it, the attacker loses everything

**Security concepts:** Platform abuse (free tier), Discord webhook as C2/exfil channel, anti-analysis defense-in-depth, debugger timing oracle (malware analysis technique applied to web phishing), post-theft redirect to real site, static hosting abuse (disposable 15KB HTML file), IP harvesting via third-party API

---

### 3. delta-executor.club -- Malware Distribution

**Category:** Fake Roblox executor distributing malware via polished marketing site

| Attribute | Value |
|-----------|-------|
| Hosting | Vercel (origin) + Cloudflare (CDN/proxy) |
| Registrar | Porkbun (WHOIS privacy) |
| TLS | Google Trust Services (Cloudflare) + Let's Encrypt R12 (Vercel origin) |
| Created | **2026-01-29 (9 days before analysis)** |
| Status at analysis | **Live (200 OK)** |

**Attack mechanics:**
- Professional Next.js App Router site with React Server Components, shadcn/ui component library, and Tailwind CSS -- unusually high build quality for malware distribution
- **Download URLs completely absent from HTML source** -- all download buttons are `<button>` elements with no `href` attributes. Actual malware URLs injected at runtime via React hydration in compiled JavaScript chunks. Static analysis tools (wget, curl, urlscan HTML capture, VirusTotal URL scan) cannot extract the download URLs without executing JavaScript.
- Offers "Delta Executor" downloads for Android (APK), Windows (EXE), and iOS
- **"Understand Antivirus Warnings" section** explicitly trains users to disable AV before running the download: "antivirus programs may occasionally flag it as a threat. These warnings are false positives, and temporarily disabling antivirus is recommended."
- Google Ads campaign (`AW-17524400036`) + GA4 (`G-1W5NLW24C4`) + GTM container (`GTM-K4TKHCNL`) + Microsoft Clarity -- the attacker is paying for ads and tracking conversion rates

**Social engineering layers:**
- 6 fake 5-star testimonials with ethnically diverse names (Alex Martinez, Sarah Chen, James Wilson, Maria Rodriguez, David Kim, Emily Thompson) -- one claims "3 months of use" on a 9-day-old domain
- "50,000+ active users" claim -- fabricated, impossible for a 9-day-old domain
- Comparison table positions Delta Executor as superior to real competitors (Hydrogen, Arceus X Neo, Fluxus); labels Arceus X Neo as "Poor (Malware history)" -- ironic projection
- schema.org FAQPage and Organization structured data for Google featured snippets
- `support@delta-executor.club` email address obfuscated by Cloudflare email-decode

**Notable findings:**
- **Chinese code comment** `// 配置 Google Ads` ("Configure Google Ads") in the gtag initialization script -- developer language artifact
- **Template reuse exposed:** OG image alt text says "Font Changer | delta-executor.club" and images hosted on Storbix CDN (`s.storbix.com`) -- the site was built from a Storbix CMS template originally designed for a font-related site
- **Google Ads ID is a pivotable identifier** -- requires a payment method, potentially traceable by law enforcement; can also be searched across other domains to find the actor's full network
- **Dual-layer hosting** -- Vercel (origin) behind Cloudflare (CDN/proxy) provides both platforms' free-tier protections (DDoS, caching, IP masking)

**Security concepts:** Client-side rendering as evasion (React hydration hides malware URLs from static analysis), antivirus dismissal as social engineering, ad-funded malware distribution economics, SEO as an attack vector (schema.org structured data, Google Ads), template/builder forensics via metadata inconsistencies

---

### 4. rbux4aall.netlify.app -- Free Robux CPA Fraud

**Category:** CPA (Cost Per Action) fraud via content locker -- no credentials stolen

| Attribute | Value |
|-----------|-------|
| Hosting | Netlify free tier (Amazon AS16509) |
| Kit | XF Content Locker (operator ID `4507479`, key `86cfc`, campaign "PrimeApps") |
| TLS | DigiCert wildcard (`*.netlify.app`) |
| Domain age | **204 days without takedown** |
| Status at analysis | **Live (200 OK)** |

**Attack mechanics -- 7-step scam funnel:**

1. Victim sees "Free Robux - Limited Time" banner with real Roblox Premium background image hotlinked from `images.rbxcdn.com`
2. Enters Roblox username; clicks "Get Robux"
3. Fake 4.5-second "Searching for \<username\>..." animation (CSS-only, no server call)
4. Robux tier selection grid: 40,000 / 20,000 / 10,000 / 5,000 Robux -- all "$0.00"
5. Fake 2.5-second "Sending Robux to \<username\>..." animation
6. "Don't miss out on this chance" CTA triggers `_WT()` function -- defined only in external XF Content Locker JavaScript
7. XF modal overlay with iframe-embedded CPA offer wall (surveys, app installs, email submits). **Operator earns $0.50-$3.00 per completed action.** No Robux is ever delivered.

**Two-stage JavaScript architecture:**
- **Stage 1:** Loader from `dfmpe7igjx4jo.cloudfront.net` reads the page config object `PxZvh_IFY_qQEzlc` (randomly generated name) containing `{it:4507479, key:'86cfc'}`
- **Stage 2:** Main script from `d1y3y09sav47f5.cloudfront.net` (filename encodes campaign params: `hVLBFSu3YKQ.4507479.86cfc.0.js`) injects the full modal apparatus -- 12 DOM elements with `xf` prefix

**6 platforms used (all free tier):** Netlify (main), 2x AWS CloudFront distributions (XF kit), Cloudflare Pages (Robux icon), Giphy (Roblox logo animation), Roblox CDN (Premium background image)

**Notable findings:**
- **OPSEC leak:** Hardcoded default text "searching for amjad ..." reveals the operator's name/alias
- **Bot detection:** `histaWts.com` analytics script returned 0 bytes to urlscan.io's crawler, suggesting active bot evasion
- **13 Blogger profile links** injected in `<head>` for SEO manipulation / search engine reputation padding
- **European number formatting** on Robux amounts (40.000 vs 40,000) suggests European operator
- **No credentials stolen** -- the entire monetization model is CPA commissions from offer wall completions

**Security concepts:** CPA fraud model (monetized via offer walls, not credential theft), commercial phishing kits (XF Content Locker), two-stage dynamic payload delivery (static HTML analysis misses entire monetization layer), cross-origin asset distribution as takedown resistance, OPSEC failures as attribution leads

---

### 5. roblox.com.ge -- Reverse Proxy + Discord OAuth Theft

**Category:** Live reverse proxy of real roblox.com with surgical code injection for Discord OAuth token theft

| Attribute | Value |
|-----------|-------|
| Hosting | WIBO Baltic UAB (AS59939, Frankfurt) |
| Nameservers | ns1.eggywall.cc / ns2.eggywall.cc |
| Kit | Eggywall reverse proxy v10.0.0 + Vaultcord Discord OAuth |
| Registrar | domenebi.ge (Georgia) |
| TLS | Let's Encrypt E8 |
| Created | 2025-08-21 (re-registration) |
| Status at analysis | **Live (403 on bare domain, 200 on path-based URLs)** |

**Attack mechanics:**

This is **not a static clone** -- the server acts as a live reverse proxy to real roblox.com. Evidence: different Roblox machine IDs per request, real GA/Sentry/analytics endpoints proxied, `data-domain='roblox.com'` in environment metadata.

The attacker injects only **3 elements** into the proxied page:

1. `<meta name='secret' data='1405351214488189'>` -- likely a Discord snowflake ID for Vaultcord session tracking
2. Login navbar `href` rewritten to `/login?returnUrl=1405351214488189` (triggers OAuth redirect instead of Roblox login)
3. **~30-line injected script** at end of `<body>`:
   - `setAvatarCardPresence('playing')` called every 300ms via `setInterval` -- fakes the profile user's online status to show them "playing" a game
   - Click hijacker on `#user-profile-header-JoinExperience` using **capture-phase event listener** (`addEventListener` with `useCapture=true`) + `stopImmediatePropagation()` to fire before any legitimate Roblox handlers
   - On click: reads secret from meta tag via `window.top.$()` (parasitically using Roblox's own jQuery), redirects to `/login?returnUrl={secret}`, which server-side redirects to Discord OAuth via `auth.immortal.rs` (Vaultcord)

**Client-capability cloaking:**
- Simple HTTP clients (curl, wget) receive a Roblox 404 error page (63,957 bytes)
- Browser-based clients receive the full reverse-proxied profile page with injected malicious script (166,075 bytes decompressed)
- Most automated threat intelligence tools miss the actual malicious payload

**Path-based routing:**
| Path | Response |
|------|----------|
| `/` (bare domain) | 403 Forbidden |
| `/users/{id}/profile` | Proxied profile page with injection (browser) or 404 error (curl) |
| `/games/{id}/{name}` | "privateServerLinkCode Required." without parameter; proxied game page with parameter |
| `/communities/{id}/` | Proxied community page with injection |
| `/login` | Server-side redirect to Discord OAuth via auth.immortal.rs |

**Domain lifecycle -- 3 phases across 4 years:**
| Phase | Period | Operator | Infrastructure |
|-------|--------|----------|---------------|
| 1. Roblox phishing (cPanel) | 2022-04 to 2023-12 | Original | Cloudflare, cPanel with mail (smtp/pop/imap/ftp/webmail), wildcard certs |
| 2. Revival | 2024-07 to 2024-12 | Same or different | Rebuilt mail infrastructure, multiple CA testing |
| 3. Discord OAuth theft | 2025-08 to present | **New operator** | Eggywall NS, WIBO Baltic hosting, no mail, single-domain cert, Vaultcord integration |

**Notable findings:**
- **3,755 urlscan.io results** (via OpenPhish) -- massive scale campaign, well-known to threat intel feeds but still operational
- **Subdomain `fuck.roblox.com.ge`** cert issued 2026-01-27 -- operator actively expanding infrastructure
- **Injected script depends on Roblox's own jQuery** (`window.top.$`) -- if Roblox removes jQuery, this injection breaks
- **URL shortener distribution** -- is.gd redirects observed pointing to roblox.com.ge paths
- **Presence spoofing** creates social engineering urgency: "this person is playing right now, I should join their game"

**Security concepts:** Reverse proxy injection (always up-to-date, defeats template-based detection), CaaS (eggywall.cc as phishing infrastructure service, Vaultcord as OAuth theft service), capture-phase event hijacking, client-capability detection (cloaking), domain lifecycle analysis via CT logs, OAuth scope abuse

---

## Cross-Cutting Patterns

### Attack technique comparison

| Capability | vercel-app | roblox-com.pl | rbux4aall | roblox.com.ge | delta-executor |
|---|---|---|---|---|---|
| **Credential harvesting** | Form -> Discord webhook | Form -> hidden JS | No (CPA fraud) | No (Discord OAuth) | No (malware) |
| **Runtime JS injection** | No (static) | Unknown (JS file not recovered) | Yes (CloudFront 2-stage) | Yes (reverse proxy) | Yes (React hydration) |
| **Anti-analysis** | 7 techniques | Directory masquerading | Bot detection pixel | Client-capability cloaking | CSR download hiding |
| **OPSEC leak** | French comments, "learning site" label | Polish comments | Operator alias "amjad" | Discord snowflake | Chinese comment, "Font Changer" template |
| **Monetization** | Stolen credentials | Stolen credentials | CPA commissions | Discord tokens | Malware installs + Google Ads revenue |
| **Hosting cost** | $0 (Vercel free) | ~$5/yr (OVH + GitHub Pages) | $0 (Netlify free) | Paid (WIBO Baltic) | ~$10/yr (Porkbun + Vercel free + Cloudflare free) |

### Key observations

1. **3/5 use runtime JavaScript injection** to evade static analysis -- three different implementations (React hydration, CloudFront two-stage bootstrap, reverse proxy injection), same evasion principle. Detection requires browser-level rendering (like urlscan.io), not just HTML fetching.

2. **5/5 used TLS** -- Let's Encrypt (2), Google Trust Services via Cloudflare/Vercel wildcards (2), DigiCert via Netlify wildcard (1). The padlock means nothing for trust. User education that says "look for https" is actively weaponized.

3. **0/5 had meaningful security headers** -- no Content-Security-Policy, no X-Content-Type-Options. Only the platform-hosted sites (Vercel, Netlify) had HSTS, and that was provided by the platform, not the attacker. However, many legitimate sites also lack these headers, so their absence alone is not a reliable indicator.

4. **5 distinct phishing kits / approaches** -- the ecosystem is fragmented. No two domains shared infrastructure, registrars, hosting, or code.

5. **The phishing supply chain is modular:**
   - **Eggywall** -- reverse proxy infrastructure as a service (nameservers, path routing, content injection, TLS provisioning)
   - **Vaultcord** -- Discord OAuth token theft as a service (customers.vaultcord.com on Vercel)
   - **XF Content Locker** -- CPA monetization kit (CloudFront-hosted, operator IDs, campaign templates)
   - **Storbix** -- site builder/CMS (templates, image hosting, one-click deployment)

6. **2/5 abuse free hosting** (Vercel, Netlify) -- zero infrastructure cost, instant deployment, trusted TLS certificates. Platform abuse teams at Vercel and Netlify are responsive, but rbux4aall persisted for 204 days without takedown.

7. **OPSEC failures on 3/5 domains** -- Polish comments, Chinese comment + "Font Changer" template leak, and hardcoded operator alias "amjad". These are attribution leads that more sophisticated operators would not leave.

---

## .ROBLOSECURITY Cookie Theft -- Broader Context

*None of the 5 analyzed domains demonstrated cookie theft. This section is desk research from Roblox DevForum announcements and Talos Intelligence, providing context on the complementary attack vector.*

### What is .ROBLOSECURITY?

The `.ROBLOSECURITY` cookie is a post-authentication session token. Once a user logs in (including completing 2FA), Roblox issues this cookie. Anyone who possesses it can authenticate as that user **without re-entering credentials or passing 2FA** -- the token is issued *after* all authentication checks complete.

### Why it matters for Roblox specifically

- **151M+ DAU, 50%+ under 13** -- a vulnerable user population with limited security awareness
- **Virtual economy with real value** -- Robux and limited items have real-money value; account takeover means financial loss for minors
- **2FA is bypassed** -- the cookie is post-authentication, making 2FA insufficient as a standalone defense

### Known attack vectors

From Talos Intelligence and Roblox DevForum reports, 6 techniques are documented:

| Vector | Description | Defense |
|--------|-------------|---------|
| JavaScript URL trick | Sharing `javascript:` URLs that steal cookies when pasted into browser address bar | Browser address bar restrictions, user education |
| Malicious bookmarklets | Social engineering to add a bookmarklet that executes cookie-stealing JS | HttpOnly flag prevents JS cookie access |
| HAR file social engineering | Tricking users into exporting HAR files (which contain session cookies) | User education, HAR sanitization tools |
| Malicious browser extensions | Extensions over-requesting permissions to access cookie store | Principle of least privilege, extension vetting |
| In-experience phishing | Fake login prompts built within Roblox games | In-game UI restrictions, content moderation |
| Cookie-stealing malware | Executables like TritonRAT, SalatStealer that read cookies from browser storage | Endpoint protection, safe browsing habits |

### Roblox's response

- **Cookie format change** scheduled for May 1, 2026
- Old formats deprecated: `_|WARNING:-DO-NOT-SHARE-THIS...|_<HexString>` and `_|WARNING:-DO-NOT-SHARE-THIS...|_GgIQAQ.<HexString>`
- Roblox recommends Open Cloud APIs with scoped credentials instead of account-level cookies for production applications

### Security concepts this connects to

- **HttpOnly flag:** Prevents JavaScript access to cookies (defense against vectors 1-4)
- **Secure flag:** Cookie only sent over HTTPS (protects against network sniffing)
- **SameSite attribute:** Prevents cross-site cookie transmission (defense against CSRF-style attacks)
- **Same-origin policy:** Why XSS on roblox.com itself would be catastrophic -- it would expose the cookie to attacker-controlled JavaScript within the same origin
- **Defense in depth:** 2FA alone is insufficient because the cookie is post-authentication. Multiple layers needed: HttpOnly + Secure + SameSite + format rotation + monitoring
- **Principle of least privilege:** Malicious browser extensions request broad permissions (`cookies`, `<all_urls>`) when they only need narrow access -- the excess permissions enable cookie theft
- **Encryption scope:** TLS protects the cookie in transit but not at rest in browser storage. A malicious extension or malware with file system access can read the cookie from the browser's cookie database.

### Connection to this project's findings

The 5 analyzed domains represent the **credential harvesting / malware / fraud** side of the Roblox threat landscape. Cookie theft is the **complementary vector** -- more dangerous because it bypasses 2FA entirely. The delta-executor.club site distributes malware that *could* include cookie stealers (the site itself doesn't steal cookies, but the downloaded payload might). Understanding both vectors is necessary for complete threat modeling.

---

## Detection & Defense Recommendations

1. **Certificate Transparency monitoring** -- Subscribe to CT log streams (certstream) and alert on new certificates containing "roblox" in the SAN list. This catches new typosquat domains at registration time. Limitation: Vercel/Netlify wildcard certs make platform-hosted phishing invisible to CT monitoring.

2. **Free-tier platform abuse reporting** -- Vercel (`vercel.com/abuse`) and Netlify (`netlify.com/abuse`) have responsive abuse teams. Report with full URL, urlscan screenshot, and description. **Both hosting and exfiltration channels must be reported** (e.g., Vercel hosting + Discord webhook for the vercel-app site).

3. **In-app URL scanning** -- Scan URLs shared in Roblox chat and messages against threat intel feeds (OpenPhish, PhishTank, Google Safe Browsing). The 75.7% profile-link-lure pattern means most phishing URLs will look like legitimate Roblox profile links.

4. **User education calibration** -- "Look for https" is actively weaponized (all 5 sites used TLS). Education should focus on **domain verification** instead. For younger users: "Does the URL end in exactly `roblox.com/`?"

5. **Cookie hardening** -- HttpOnly, Secure, SameSite=Strict, and format rotation (already planned for May 2026). The format change forces attackers to update their tooling, creating a window where older cookie-stealing scripts break.

6. **Static analysis is insufficient** -- 3/5 domains hide malicious payloads via runtime JavaScript injection. Detection needs browser-level rendering (urlscan.io, headless browser sandboxes) to capture the true page content. The roblox.com.ge site additionally requires client-capability detection bypass (it serves different content to curl vs. browsers).

---

## Incident Response: Takedown Playbook

*Structured using the NIST IR lifecycle*

### Detect

- Certificate Transparency monitoring for new "roblox" typosquats (crt.sh, certstream)
- urlscan.io community feeds for new scans matching Roblox branding
- Monitor the .com.kz registrar space -- 426 domains (21.3% of dataset) suggest concentrated infrastructure worth tracking

### Contain & Eradicate

| Domain type | Primary report target | Expected response | Secondary |
|---|---|---|---|
| Platform-hosted (Vercel, Netlify) | Platform abuse team | Hours | Google Safe Browsing |
| Registered domain (roblox-com.pl, delta-executor.club) | Registrar abuse contact | Days | Google Safe Browsing, PhishTank |
| Cloudflare-fronted (delta-executor.club) | Cloudflare abuse + registrar | Days (Cloudflare may only remove proxy) | Origin IP may be exposed in CT logs |
| CaaS-backed (roblox.com.ge via eggywall.cc) | Registrar + upstream hosting (WIBO Baltic UAB) | Days-weeks | Report eggywall.cc nameservers as malicious infrastructure |

### Recover & Lessons Learned

- **Monitor for respawn:** roblox-com.pl demonstrates that partial takedown (content removed, infrastructure intact) leaves domains redeployable in minutes. TLS cert was renewed *after* content removal.
- **Speed of deployment:** delta-executor.club was fully operational (Next.js site + Google Ads + analytics) within 9 days of domain registration
- **Takedown is whack-a-mole** without upstream disruption -- registrar-level blocks and CaaS infrastructure takedowns (eggywall.cc, Vaultcord) have more lasting impact than individual domain takedowns
- **Evidence preservation:** HTML snapshots, urlscan DOM captures, and WHOIS snapshots should be taken immediately -- domains can go down at any time (roblox-com.pl content disappeared between recon sessions)

---

## Appendix: Data Sources

| Source | Type | URL |
|--------|------|-----|
| Phishing.Database | GitHub blocklist | github.com/mitchellkrogza/Phishing.Database |
| crt.sh | Certificate Transparency search | crt.sh |
| urlscan.io | URL scanning + DOM capture | urlscan.io |
| OpenPhish | Active phishing feed | openphish.com |
| Phishing.Army | Aggregated blocklist | phishing.army |
| phishing-filter | Curated domain list | github.com/nickspaargaren/pihole-google |
| PhishTank | Community-reported phishing | phishtank.org |
| Roblox DevForum | Official community | devforum.roblox.com |
| Talos Intelligence | Threat research blog | blog.talosintelligence.com |
