# Process Log

Tracks decisions, results, and notes as we execute the plan.

---

## Phase 1A: Setup + Automated Collection — COMPLETE (Feb 7, 2026)

### Results

**1,995 unique Roblox phishing URLs** collected and deduplicated.

| Source | Unique URLs | Notes |
|--------|------------|-------|
| GitHub:Phishing.Database | 1,669 | Massive validated blocklist, bulk of data |
| crt.sh | 186 | Certificate transparency — suspicious domains with "roblox" |
| urlscan.io | 84 | Scanned pages, screenshots/evidence available |
| OpenPhish | 26 | Current active feed, high-confidence |
| GitHub:Phishing.Army | 23 | Aggregated blocklist |
| PhishTank | 8 | CSV feed, limited Roblox entries |
| GitHub:phishing-filter | 7 | Curated domain list |

8 entries appeared in multiple sources (cross-validated).

### Decisions Made

1. **urlscan.io wildcard queries require API key** — switched to non-wildcard queries (`domain:roblox AND NOT domain:roblox.com`, `page.title:"roblox"`). Got 84 results.
2. **URLhaus had 0 Roblox entries** in the recent feed — the malware entries (LuaLoader, SalatStealer) from prior testing have aged out. Keep the source in collect.py for future runs but don't count on it.
3. **PhishTank target field unreliable** — Roblox entries labeled as "Other" not "Roblox". Filtering by URL content instead.
4. **Dataset far exceeds the 50-100 target** (1,995 vs 100). Phase 1C will need to categorize all but we have more than enough for analysis.
5. **python3 required** (not `python`) — pyenv maps `python3` to 3.12.4.

### Files Produced

- `data/samples_raw.json` — 1,995 deduplicated entries with source attribution
- `data/raw/` — 12 raw dump files from each source
- `collect.py` — rerunnable collection script

### Observations

- Phishing.Database dominates the count (84% of entries). Many may be historical/dead but useful for pattern analysis.
- crt.sh gives domain-level data (no specific phishing paths) — good for typosquatting analysis but needs enrichment.
- urlscan.io entries are the richest — they have pre-captured screenshots and DOM snapshots we can reference.
- OpenPhish entries are the most current (active feed) — best candidates for live-site evidence capture.

---

## Phase 1B: Community Sources + Threat Reports — COMPLETE (Feb 7, 2026)

### Results

**5 new phishing domains** merged into `samples_raw.json` (now 1,999 total after removing 1 false positive).

| Source | URLs Added | Context Data | Notes |
|--------|-----------|-------------|-------|
| DevForum: Security Alert post | 3 domains (`roblox.com.sc`, `accounts-roblox.com`, `noreply-roblox.com`) | Fake password reset flow, "old password" field, real avatar display | High-value attack pattern documentation |
| DevForum: Cookie Format Changes | 0 | Both deprecated `.ROBLOSECURITY` formats, May 2026 deadline | Critical for Phase 2B |
| phish.report IOK | 0 | 2 IOK rule paths found, 1 fetched in detail | Detection signatures for Phase 3 |
| Talos Intelligence Blog | 0 (3 false positives removed) | 6 attack technique descriptions | Rich technique catalog for ATTACK_VECTORS.md |
| Roblox Wiki | 2 domains (`rcblcx.com`, `ww-roblox.com`) | Scam taxonomy, self-XSS, cookie theft | 403 Forbidden — used known data from prior testing |
| Reddit r/roblox | 0 | 45 unique posts, 14 image-only | Social engineering context only, no extractable URLs |

### Decisions Made

1. **Roblox Wiki returned 403 Forbidden** — Fandom may be blocking automated requests. Used known domain examples from prior manual testing.
2. **Reddit confirms ~31% image-only scam posts** — phishing URLs are in screenshots, not text. Reddit is valuable for social engineering context (victim narratives, lure descriptions) but not URL extraction.
3. **Talos blog produced false positive "domains"** (image filenames like `RobloxWarning.jpg`) — caught and removed during QA. No real phishing domains in the blog text.
4. **DevForum JSON API works well** — `.json` suffix on topic URLs returns structured data with all posts.
5. **Removed `rbx.okta.com` false positive** — legitimate Roblox corporate SSO endpoint (Okta), with redirect to `ros.rbx.com`. Was captured by urlscan.io in Phase 1A.

### Files Produced

- `data/raw/devforum_security_alert.json` — phishing domains + attack flow details
- `data/raw/devforum_cookie_changes.json` — `.ROBLOSECURITY` cookie format info
- `data/raw/phishreport_iok_rules.json` — IOK detection signatures
- `data/raw/talos_techniques.json` — 6 attack technique descriptions
- `data/raw/roblox_wiki_scams.json` — community-documented scam patterns
- `data/raw/reddit_context.json` — 45 scam-related posts from r/roblox
- `collect_1b.py` — rerunnable Phase 1B collection script

### Observations

- DevForum is the highest-value community source — real phishing domains cited by Roblox staff.
- The "Security Alert" phishing campaign is well-documented: fake password reset emails showing the victim's real Roblox avatar, with an "old password" field that legitimate resets never use.
- Talos Intelligence blog is best as a technique reference (6 attack methods), not as a domain source.
- Reddit r/roblox has tons of scam reports but nearly all evidence is in screenshots (images), not extractable text.
- `.ROBLOSECURITY` cookie formats confirmed from DevForum: the `_|WARNING:...|_` prefix pattern with hex string payload.

---

## Phase 1C: Categorization + Metadata — COMPLETE (Feb 7, 2026)

### Results

**1,999 entries fully categorized** in `data/samples.json` with metadata: category, typosquat technique, lure type, TLD, and active/dead status.

#### Category Distribution

| Category | Count | % | Notes |
|----------|------:|----:|-------|
| ccTLD_abuse | 1,348 | 67.4% | roblox.com registered under foreign TLDs |
| typosquatting | 564 | 28.2% | Character modifications to "roblox" |
| other | 81 | 4.0% | GitHub Pages-hosted phishing, misc |
| malware_download | 4 | 0.2% | .exe/.zip download lures |
| url_shortener | 2 | 0.1% | Shortened links to phishing |
| credential_harvest | 0 | 0.0% | After removing rbx.okta.com false positive |

#### Typosquatting Technique Distribution

| Technique | Count | % | Notes |
|-----------|------:|----:|-------|
| ccTLD_append | 1,348 | 67.4% | roblox.com.kz, roblox.com.do, etc. |
| prefix_addition | 370 | 18.5% | myroblox, getroblox, etc. |
| char_addition | 97 | 4.9% | robloxc, robloxia, etc. |
| none | 86 | 4.3% | No typosquatting — uses unrelated domains |
| hyphen_insertion | 73 | 3.6% | www-roblox, roblox-login, etc. |
| char_substitution | 23 | 1.1% | robiox, r0blox, rcblcx |
| protocol_in_domain | 3 | 0.1% | httpss-roblox.co |

#### Lure Type Distribution

| Lure Type | Count | % | Notes |
|-----------|------:|----:|-------|
| profile_link | 1,514 | 75.7% | Mimicking /users/ID/profile |
| other | 350 | 17.5% | Domain-only, no specific path |
| private_server_link | 114 | 5.7% | ?privateServerLinkCode= parameter |
| login_page | 11 | 0.5% | Direct /login page |
| community_link | 9 | 0.4% | /communities/ or /groups/ |
| robux_purchase | 2 | 0.1% | /upgrades/robux |

#### Top 10 TLDs

| TLD | Count | % |
|-----|------:|----:|
| .com | 488 | 24.4% |
| .com.kz | 426 | 21.3% |
| .com.do | 114 | 5.7% |
| .com.gl | 108 | 5.4% |
| .com.lr | 85 | 4.2% |
| .com.ms | 80 | 4.0% |
| .com.ht | 76 | 3.8% |
| .com.mu | 73 | 3.6% |
| .com.sb | 68 | 3.4% |
| .com.et | 57 | 2.9% |

#### Active/Dead Status

| Status | Count | % |
|--------|------:|----:|
| dead | 1,789 | 89.5% |
| active | 83 | 4.2% |
| ssl_error | 65 | 3.2% |
| possibly_active | 62 | 3.1% |
| timeout | 1 | 0.1% |

### Decisions Made

1. **ccTLD abuse is the dominant technique** (67.4%) — attackers register "roblox.com" under foreign country-code TLDs. This was not obvious before categorization; the sheer scale of .com.kz (Kazakhstan) abuse is striking.
2. **Profile link is the dominant lure** (75.7%) — mimicking `/users/ID/profile` pages. This makes sense: profile links are commonly shared in Roblox social contexts.
3. **89.5% of URLs are dead** — expected for a historical dataset. The 83 active sites and 62 possibly-active (behind WAF) are candidates for Phase 1D evidence capture.
4. **Removed `rbx.okta.com` as false positive** — legitimate Roblox corporate SSO (Okta), caught during QA review of active entries.
5. **40 concurrent workers for status checks** — completed 2,000 HEAD requests in ~3 minutes.

### Files Produced

- `data/samples.json` — 1,999 entries with full metadata schema
- `categorize.py` — rerunnable categorization script

### Observations

- **Kazakhstan (.com.kz) dominates** at 21.3% of all entries — a single registrar/infrastructure may be behind many of these.
- **Profile link lures** dominate because they're the most natural thing to share in Roblox social interactions ("check out my profile").
- **Private server invite links** (5.7%) are the second most specific lure — attackers exploit the `?privateServerLinkCode=` parameter pattern.
- **Very few login-page-only phishing** (0.5%) — most attackers create full-page clones of specific Roblox pages rather than generic login forms.
- **Character substitution is rare** (1.1%) compared to ccTLD abuse — it's easier to register roblox.com.kz than to find an available misspelling of roblox.com.

---

## Phase 1: Infrastructure Reconnaissance — COMPLETE (Feb 7, 2026)

### Tools Used

| Tool | Purpose | Notes |
|------|---------|-------|
| `dig` | DNS resolution (A, AAAA, NS, MX, TXT records) | Used for all 5 domains |
| `whois` | Domain registration data | Used for 3 registered domains (skipped Vercel/Netlify subdomains) |
| `curl -sI -L` | HTTP response headers + redirect chains | Used for all 5 domains |
| `openssl s_client` + `x509` | TLS certificate details (issuer, validity, SANs) | Used for all 5 domains |
| `crt.sh` API | Certificate Transparency history | Used for all 5 domains; empty for wildcard-covered subdomains |
| `ipinfo.io` API | IP geolocation, ASN, hosting provider | Used for all resolved IPs |
| `dig -x` | Reverse DNS (PTR records) | Used for all resolved IPs |
| `urlscan.io` API | Scan results, verdicts, external resources, screenshots | Used for 4 domains (3 with existing refs + 1 search query) |

### Results

**5 domain teardown JSONs** written to `data/teardowns/`.

| Domain | Hosting | CDN | TLS Issuer | Registrar | Key Finding |
|--------|---------|-----|------------|-----------|-------------|
| `roblox-com.pl` | GitHub Pages | Fastly | Let's Encrypt R13 | OVH SAS (France) | CT logs link to `roblox-com.us` via shared SAN — same operator runs multiple ccTLD phishing domains. Two-phase operation: Jan 2023, then reactivated Nov 2025. Currently 404 (content removed, infra intact). |
| `vercel.app` site | Vercel (free tier) | Vercel Edge | Google Trust Services (wildcard `*.vercel.app`) | N/A (subdomain) | Discord webhook exfiltration (`1408202683021529099`). Calls `api.ipify.org` for victim IP. Loads Roblox logo from Wikimedia. French-language targeting. |
| `delta-executor.club` | Vercel (origin) | Cloudflare | Cloudflare (Google TS) + Let's Encrypt (origin) | Porkbun | Only 9 days old at analysis. Google Ads campaign (`AW-17524400036`) + GA4 (`G-1W5NLW24C4`) — attacker paying for ads. Google Site Verification TXT record. Cloudflare Email Routing configured. |
| `rbux4aall.netlify.app` | Netlify (free tier) | Netlify Edge | DigiCert (wildcard `*.netlify.app`) | N/A (subdomain) | 204-day persistence without takedown. Multi-platform assets (Netlify + Cloudflare Pages + CloudFront + Giphy). CPA fraud indicators (`check.php` tracking). Fake testimonial images. |
| `roblox.com.ge` | WIBO Baltic UAB (Frankfurt) | None | Let's Encrypt E8 | domenebi.ge (Georgian) | 28 CT certs reveal 3-phase lifecycle: (1) full cPanel phishing host 2022-2023, (2) revival mid-2024, (3) re-registered Aug 2025 by new operator using `eggywall.cc` infra for Discord OAuth theft via Vaultcord. 3,755 urlscan.io results. |

### Decisions Made

1. **WHOIS skipped for Vercel/Netlify subdomains** — returns Vercel Inc/Netlify Inc corporate data, not attacker data. Documented as "free-tier platform abuse."
2. **roblox-com.pl currently returns 404** — phishing content was taken down (likely GitHub abuse report) but all infrastructure remains intact (DNS, TLS, email). This is itself a finding about takedown effectiveness.
3. **roblox.com.ge had 3,755 urlscan.io results** — far more than expected. The domain has been heavily reported by OpenPhish.
4. **delta-executor.club Google Ads ID is a strong attribution pivot** — requires payment method, potentially traceable.
5. **Vaultcord infrastructure is separate** — `auth.immortal.rs` CNAMEs to `customers.vaultcord.com` on Vercel. Vaultcord is a third-party cybercrime-as-a-service for Discord OAuth theft.

### Files Produced

- `data/teardowns/roblox-com-pl.json` — 10.8 KB, GitHub Pages-hosted ccTLD login clone
- `data/teardowns/vercel-app.json` — 12.0 KB, Vercel-hosted French credential harvester
- `data/teardowns/delta-executor-club.json` — 16.4 KB, Cloudflare+Vercel malware distribution
- `data/teardowns/rbux4aall-netlify.json` — 11.0 KB, Netlify-hosted free Robux scam
- `data/teardowns/roblox-com-ge.json` — 20.5 KB, 3-phase domain lifecycle + Discord OAuth theft

### Cross-Domain Observations

- **3/5 domains use free hosting** — GitHub Pages (`roblox-com.pl`), Vercel (`vercel.app` site, + origin for `delta-executor.club`), Netlify (`rbux4aall`). Zero-cost phishing infrastructure is the norm.
- **All 5 use free TLS** — Let's Encrypt (2), Google Trust Services via Cloudflare/Vercel wildcards (2), DigiCert via Netlify wildcard (1). Padlock icon means nothing for trust.
- **Wildcard certs create CT blind spots** — `vercel.app` and `netlify.app` subdomains are invisible in Certificate Transparency logs because they ride parent wildcards. Only domains with their own registrations appear in crt.sh.
- **Security headers uniformly absent** — None of the 5 domains serve CSP, X-Content-Type-Options, or Permissions-Policy. Only the platform-hosted sites (Vercel, Netlify) have HSTS — provided by the platform, not the attacker.
- **3 distinct exfiltration mechanisms observed** — Discord webhook (Vercel site), form POST (roblox-com.pl), Discord OAuth redirect (roblox.com.ge). Phase 2 content analysis will map these fully.
- **`eggywall.cc` is a phishing infrastructure service** — custom nameservers, `Apache/2.4.52 (Ubuntu)` with custom `Eggy-Wall: 10.0.0` header and `Abuse: abuse@eggywall.cc` contact. Worth deeper investigation.
- **delta-executor.club is the most commercially operated** — Google Ads, GA4, Cloudflare Email Routing, Porkbun registration, all within 9 days of domain creation. This is a business, not a hobbyist.
