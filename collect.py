#!/usr/bin/env python3
"""
Roblox Phishing URL Collector — Phase 1A
Pulls from all automated threat intel sources, deduplicates,
and produces data/samples_raw.json with source attribution.
"""

import csv
import io
import json
import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import tldextract

# --- Configuration ---

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
OUTPUT_FILE = os.path.join(BASE_DIR, "data", "samples_raw.json")

# Legitimate Roblox domains to exclude
LEGIT_ROBLOX_DOMAINS = {
    "roblox.com",
    "rbxcdn.com",
    "roblox.qq.com",
    "robloxlabs.com",
    "simulprod.com",
    "rbx.com",
    "roblox.cn",
    "robloxdev.com",
}

ROBLOX_PATTERN = re.compile(r"robl[o0]x", re.IGNORECASE)

HEADERS = {
    "User-Agent": "RobloxPhishingResearch/1.0 (academic threat intelligence research)"
}

collected_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")


def is_legit_roblox(domain: str) -> bool:
    """Check if a domain is a legitimate Roblox property."""
    ext = tldextract.extract(domain)
    registered = f"{ext.domain}.{ext.suffix}"
    return registered.lower() in LEGIT_ROBLOX_DOMAINS


def has_roblox_ref(text: str) -> bool:
    """Check if text contains a roblox reference."""
    return bool(ROBLOX_PATTERN.search(text))


def normalize_url(url: str) -> str:
    """Normalize URL for deduplication."""
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def extract_domain(url: str) -> str:
    """Extract the full domain from a URL."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return parsed.netloc.lower().split(":")[0]
    except Exception:
        return url.lower()


# --- Source Collectors ---


def collect_openphish() -> list[dict]:
    """Collect Roblox phishing URLs from OpenPhish free feed."""
    print("\n[OpenPhish] Fetching feed...")
    url = "https://openphish.com/feed.txt"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        raw_path = os.path.join(RAW_DIR, "openphish_feed.txt")
        with open(raw_path, "w") as f:
            f.write(resp.text)

        lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
        total = len(lines)
        results = []
        for line in lines:
            domain = extract_domain(line)
            if has_roblox_ref(line) and not is_legit_roblox(domain):
                results.append({
                    "url": normalize_url(line),
                    "domain": domain,
                    "source": "OpenPhish",
                })
        print(f"  Total feed URLs: {total}")
        print(f"  Roblox phishing URLs: {len(results)}")
        return results
    except Exception as e:
        print(f"  ERROR: {e}")
        return []


def collect_crtsh() -> list[dict]:
    """Collect suspicious Roblox-like domains from crt.sh certificate transparency."""
    print("\n[crt.sh] Fetching certificates with 'roblox' in domain...")
    url = "https://crt.sh/?q=%25roblox%25&output=json"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=60)
        resp.raise_for_status()
        certs = resp.json()
        raw_path = os.path.join(RAW_DIR, "crtsh_certs.json")
        with open(raw_path, "w") as f:
            json.dump(certs, f, indent=2)

        # Extract unique domains from common_name and name_value fields
        domains = set()
        for cert in certs:
            for field in ["common_name", "name_value"]:
                val = cert.get(field, "")
                for name in val.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and has_roblox_ref(name) and not is_legit_roblox(name):
                        domains.add(name.lower())

        results = []
        for domain in sorted(domains):
            results.append({
                "url": f"https://{domain}",
                "domain": domain,
                "source": "crt.sh",
            })
        print(f"  Total certs returned: {len(certs)}")
        print(f"  Unique suspicious Roblox domains: {len(results)}")
        return results
    except Exception as e:
        print(f"  ERROR: {e}")
        return []


def collect_github_blocklist(name: str, url: str) -> list[dict]:
    """Collect Roblox phishing URLs from a GitHub-hosted blocklist."""
    print(f"\n[GitHub: {name}] Fetching blocklist...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=60)
        resp.raise_for_status()
        raw_path = os.path.join(RAW_DIR, f"github_{name.replace('/', '_').replace('.', '_')}.txt")
        with open(raw_path, "w") as f:
            f.write(resp.text)

        lines = [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith(("#", "!"))]
        total = len(lines)
        results = []
        for line in lines:
            # Some lists are domains-only, some are full URLs
            if has_roblox_ref(line):
                domain = extract_domain(line)
                if not is_legit_roblox(domain):
                    results.append({
                        "url": normalize_url(line),
                        "domain": domain,
                        "source": f"GitHub:{name}",
                    })
        print(f"  Total entries: {total}")
        print(f"  Roblox phishing URLs: {len(results)}")
        return results
    except Exception as e:
        print(f"  ERROR: {e}")
        return []


def collect_urlscan() -> list[dict]:
    """Collect Roblox phishing URLs from urlscan.io search API."""
    print("\n[urlscan.io] Searching for malicious Roblox scans...")
    url = "https://urlscan.io/api/v1/search/"
    results_all = []

    # Free API: no wildcards, no verdicts filter — use simple domain/title queries
    queries = [
        'domain:roblox AND NOT domain:roblox.com',
        'page.title:"roblox" AND NOT domain:roblox.com',
        'domain:robux',
        'domain:robiox',
        'domain:r0blox',
    ]

    for query in queries:
        try:
            params = {"q": query, "size": 100}
            resp = requests.get(url, params=params, headers=HEADERS, timeout=30)
            if resp.status_code == 429:
                print(f"  Rate limited, waiting 5s...")
                time.sleep(5)
                resp = requests.get(url, params=params, headers=HEADERS, timeout=30)
            if resp.status_code == 403:
                print(f"  Query '{query[:40]}': 403 Forbidden (needs API key), skipping")
                continue
            resp.raise_for_status()
            data = resp.json()
            safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', query[:30])
            raw_path = os.path.join(RAW_DIR, f"urlscan_{safe_name}.json")
            with open(raw_path, "w") as f:
                json.dump(data, f, indent=2)

            count = 0
            for result in data.get("results", []):
                page = result.get("page", {})
                page_url = page.get("url", "")
                scan_id = result.get("_id", "")

                if not page_url:
                    continue

                domain = extract_domain(page_url)
                if is_legit_roblox(domain):
                    continue

                # Only include if it has a roblox reference
                if has_roblox_ref(page_url) or has_roblox_ref(page.get("title", "")):
                    results_all.append({
                        "url": normalize_url(page_url),
                        "domain": domain,
                        "source": "urlscan.io",
                        "urlscan_ref": f"https://urlscan.io/result/{scan_id}/" if scan_id else "",
                    })
                    count += 1

            print(f"  Query '{query[:45]}': {count} Roblox URLs from {len(data.get('results', []))} results")
            time.sleep(2)  # Rate limiting — be polite
        except Exception as e:
            print(f"  ERROR for query '{query[:40]}': {e}")

    # Deduplicate within urlscan results
    seen = set()
    unique = []
    for r in results_all:
        if r["url"] not in seen:
            seen.add(r["url"])
            unique.append(r)

    print(f"  Total unique Roblox phishing URLs: {len(unique)}")
    return unique


def collect_urlhaus() -> list[dict]:
    """Collect Roblox-related entries from URLhaus recent feed."""
    print("\n[URLhaus] Fetching recent feed...")
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        raw_path = os.path.join(RAW_DIR, "urlhaus_recent.json")
        # data can be large; just save entry count
        entries = list(data.values()) if isinstance(data, dict) else data
        with open(raw_path, "w") as f:
            json.dump({"total_entries": len(entries), "roblox_entries": []}, f, indent=2)

        results = []
        roblox_entries = []
        for entry in entries:
            entry_url = entry.get("url", "") if isinstance(entry, dict) else ""
            if has_roblox_ref(entry_url):
                domain = extract_domain(entry_url)
                if not is_legit_roblox(domain):
                    results.append({
                        "url": normalize_url(entry_url),
                        "domain": domain,
                        "source": "URLhaus",
                        "notes": f"threat_type: {entry.get('threat', 'unknown')}",
                    })
                    roblox_entries.append(entry)

        # Save roblox entries to raw
        with open(raw_path, "w") as f:
            json.dump({"total_entries": len(entries), "roblox_entries": roblox_entries}, f, indent=2)

        print(f"  Total feed entries: {len(entries)}")
        print(f"  Roblox-related entries: {len(results)}")
        return results
    except Exception as e:
        print(f"  ERROR: {e}")
        return []


def collect_phishtank() -> list[dict]:
    """Collect Roblox phishing URLs from PhishTank CSV feed."""
    print("\n[PhishTank] Fetching CSV feed...")
    url = "http://data.phishtank.com/data/online-valid.csv"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=120)
        resp.raise_for_status()
        raw_path = os.path.join(RAW_DIR, "phishtank_online.csv")
        with open(raw_path, "w") as f:
            f.write(resp.text)

        reader = csv.DictReader(io.StringIO(resp.text))
        total = 0
        results = []
        for row in reader:
            total += 1
            phish_url = row.get("url", "")
            if has_roblox_ref(phish_url):
                domain = extract_domain(phish_url)
                if not is_legit_roblox(domain):
                    results.append({
                        "url": normalize_url(phish_url),
                        "domain": domain,
                        "source": "PhishTank",
                        "notes": f"phish_id: {row.get('phish_id', '')}, target: {row.get('target', '')}",
                    })
        print(f"  Total verified phishing entries: {total}")
        print(f"  Roblox phishing URLs: {len(results)}")
        return results
    except Exception as e:
        print(f"  ERROR: {e}")
        return []


# --- Deduplication & Output ---


def deduplicate(all_entries: list[dict]) -> list[dict]:
    """Deduplicate URLs across sources, preserving all source attributions."""
    url_map: dict[str, dict] = {}
    for entry in all_entries:
        url = entry["url"]
        if url in url_map:
            # Merge sources
            existing = url_map[url]
            existing_sources = existing["sources"] if isinstance(existing.get("sources"), list) else [existing.get("source", "")]
            new_source = entry.get("source", "")
            if new_source and new_source not in existing_sources:
                existing_sources.append(new_source)
            existing["sources"] = existing_sources
            # Keep urlscan ref if available
            if entry.get("urlscan_ref") and not existing.get("urlscan_ref"):
                existing["urlscan_ref"] = entry["urlscan_ref"]
            # Merge notes
            if entry.get("notes") and entry["notes"] not in existing.get("notes", ""):
                existing["notes"] = (existing.get("notes", "") + "; " + entry["notes"]).strip("; ")
        else:
            entry["sources"] = [entry.pop("source", "unknown")]
            url_map[url] = entry

    # Assign IDs
    results = []
    for i, (url, entry) in enumerate(sorted(url_map.items()), start=1):
        entry["id"] = i
        entry["collected_date"] = collected_date
        results.append(entry)
    return results


def main():
    print("=" * 60)
    print("Roblox Phishing URL Collector — Phase 1A")
    print(f"Date: {collected_date}")
    print("=" * 60)

    all_entries = []

    # --- Primary Sources ---
    all_entries.extend(collect_openphish())
    all_entries.extend(collect_crtsh())

    # GitHub blocklists
    github_sources = [
        ("Phishing.Database", "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"),
        ("phishing-filter", "https://curbengh.github.io/phishing-filter/phishing-filter-domains.txt"),
        ("Phishing.Army", "https://phishing.army/download/phishing_army_blocklist_extended.txt"),
    ]
    for name, url in github_sources:
        all_entries.extend(collect_github_blocklist(name, url))

    all_entries.extend(collect_urlscan())

    # --- Secondary Sources ---
    all_entries.extend(collect_urlhaus())
    all_entries.extend(collect_phishtank())

    # --- Deduplicate & Save ---
    print("\n" + "=" * 60)
    print("Deduplicating across all sources...")
    deduped = deduplicate(all_entries)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(deduped, f, indent=2)

    print(f"\nTotal raw entries collected: {len(all_entries)}")
    print(f"Unique URLs after dedup: {len(deduped)}")
    print(f"Output: {OUTPUT_FILE}")

    # Per-source breakdown
    source_counts: dict[str, int] = {}
    for entry in deduped:
        for src in entry.get("sources", []):
            source_counts[src] = source_counts.get(src, 0) + 1

    print("\nPer-source counts (unique URLs):")
    for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"  {src}: {count}")

    print(f"\nRaw dumps saved to: {RAW_DIR}/")
    print("Done!")


if __name__ == "__main__":
    main()
