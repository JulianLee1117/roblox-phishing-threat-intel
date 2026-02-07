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

## Phase 1B: Manual + Automated Sources — PENDING

(Next phase)
