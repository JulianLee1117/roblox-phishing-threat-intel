# Roblox Phishing Threat Intelligence

Independent security research analyzing phishing threats targeting Roblox's 65M+ daily active users. Built a collection pipeline across 7 threat intelligence sources, gathered 1,999 phishing URLs, and performed deep infrastructure and content analysis on 5 live domains across 4 attack categories.

## Key Findings

- **1,999 phishing URLs** collected from 7 sources (Phishing.Database, crt.sh, urlscan.io, OpenPhish, PhishTank, Phishing.Army, phishing-filter)
- **84% from one blocklist** -- data skew motivated a pivot from broad collection to deep analysis of 5 representative domains
- **5 domains torn down** across credential harvesting, malware distribution, CPA fraud, and Discord OAuth token theft
- **3/5 use runtime JavaScript injection** to hide malicious payloads from static analysis -- React hydration, CloudFront two-stage bootstrap, and reverse proxy injection
- **5/5 used TLS** -- Let's Encrypt is free; the padlock means nothing for trust
- **Phishing supply chain is modular:** Eggywall (reverse proxy infra), Vaultcord (Discord OAuth theft), XF Content Locker (CPA monetization), Storbix (site templates)
- **0/5 used cookie theft** -- but .ROBLOSECURITY cookie theft is the complementary vector Roblox is actively hardening against (format change May 2026)

## Deliverable

**[THREAT_BRIEF.md](THREAT_BRIEF.md)** -- Full threat brief with 5 domain teardowns, cross-cutting pattern analysis, .ROBLOSECURITY cookie context, detection recommendations, and incident response takedown playbook.

## Repo Structure

```
.
├── THREAT_BRIEF.md              # Primary deliverable -- full threat brief
├── alternate-plan.md            # Analysis plan with phase definitions and interview prep
├── process.md                   # Execution log tracking decisions and results
├── collect.py                   # Phase 1A: automated collection pipeline (7 sources)
├── collect_1b.py                # Phase 1B: community source collection
├── categorize.py                # Phase 1C: URL categorization and status checking
├── data/
│   ├── samples.json             # 1,999 categorized entries (primary dataset)
│   ├── samples_raw.json         # Raw deduplicated entries before categorization
│   ├── raw/                     # Source-specific raw data (12 files)
│   │   ├── devforum_cookie_changes.json
│   │   ├── devforum_security_alert.json
│   │   ├── talos_techniques.json
│   │   └── ...
│   ├── teardowns/               # 5 domain teardown JSONs (infrastructure + content analysis)
│   │   ├── roblox-com-pl.json
│   │   ├── vercel-app.json
│   │   ├── delta-executor-club.json
│   │   ├── rbux4aall-netlify.json
│   │   └── roblox-com-ge.json
│   └── html_snapshots/          # 10 HTML snapshots (live fetches + urlscan DOM captures)
```

## 5 Analyzed Domains

| # | Domain | Category | Key Finding |
|---|--------|----------|-------------|
| 1 | `roblox-com.pl` | ccTLD login clone | 28 locally-scraped CSS files, 3 credential harvesting vectors, Polish operator, CT logs link to sibling domain `roblox-com.us` |
| 2 | `www-roblox-com-frr-users-*.vercel.app` | French credential harvester | Dual Discord webhook (visitor beacon + credential theft), 7 anti-analysis techniques, zero obfuscation |
| 3 | `delta-executor.club` | Malware distribution | Next.js + Google Ads-funded, download URLs hidden via React hydration, AV dismissal training, 9 days old |
| 4 | `rbux4aall.netlify.app` | Free Robux CPA fraud | XF Content Locker kit, 7-step scam funnel, operator alias "amjad" leaked, 204-day persistence |
| 5 | `roblox.com.ge` | Reverse proxy + Discord OAuth | Live reverse proxy of real roblox.com, only 3 injected elements, client-capability cloaking, 3-phase domain lifecycle over 4 years |

## Data Sources

| Source | URLs | Type |
|--------|-----:|------|
| Phishing.Database | 1,669 | GitHub blocklist |
| crt.sh | 186 | Certificate Transparency |
| urlscan.io | 83 | URL scanning + DOM capture |
| OpenPhish | 26 | Active phishing feed |
| Phishing.Army | 23 | Aggregated blocklist |
| PhishTank | 8 | Community-reported |
| phishing-filter | 7 | Curated domain list |
| DevForum + Roblox Wiki | 5 | Manual community sources |

## Tools Used

DNS (`dig`), WHOIS, HTTP headers (`curl`), TLS certificates (`openssl`), Certificate Transparency (`crt.sh`), IP geolocation (`ipinfo.io`), URL scanning (`urlscan.io`), Python 3.12 for collection and categorization.

## Ethical Considerations

- **Passive observation only** -- no credentials submitted, no forms interacted with, no malware downloaded, no phishing infrastructure probed beyond what is publicly accessible
- **Standard reconnaissance tools** -- DNS queries, WHOIS lookups, HTTP HEAD/GET requests, Certificate Transparency searches, and publicly-cached urlscan.io data
- **No interaction with victims** -- analysis focused on attacker infrastructure and techniques, not on tracking or identifying victims
- **Responsible disclosure** -- phishing domains identified here should be reported to the appropriate registrars, hosting providers, and threat intel feeds
