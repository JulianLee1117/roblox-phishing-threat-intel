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
