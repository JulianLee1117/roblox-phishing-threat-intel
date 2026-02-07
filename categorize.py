#!/usr/bin/env python3
"""
Roblox Phishing Categorizer — Phase 1C
Applies metadata schema to every entry in samples_raw.json:
  - category (ccTLD_abuse, typosquatting, free_robux, fake_reset, etc.)
  - lure_type (private_server_link, profile_link, game_link, etc.)
  - typosquat_technique (ccTLD_append, char_substitution, etc.)
  - TLD extraction
  - active/dead status check (concurrent HTTP HEAD requests)
Produces data/samples.json with statistics.
"""

import json
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import tldextract

# --- Configuration ---

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(BASE_DIR, "data", "samples_raw.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "data", "samples.json")

# Concurrency for status checks
MAX_WORKERS = 40
HEAD_TIMEOUT = 8

# --- Domain Analysis Helpers ---

# Known legitimate Roblox-related domains (not phishing)
LEGIT_DOMAINS = {
    "roblox.com", "rbxcdn.com", "roblox.qq.com", "robloxlabs.com",
    "simulprod.com", "rbx.com", "roblox.cn", "robloxdev.com",
    "roblox.fandom.com",
}

# ccTLDs commonly abused for roblox.com.XX pattern
# These are country-code TLDs where attackers register "roblox.com" directly
CCTLD_ABUSE_TLDS = {
    "ml", "ga", "cf", "tk", "gq",  # Free African ccTLDs
    "py", "ge", "mq", "gf", "tc", "ps", "sc", "ws", "ms", "gg",
    "co", "pl", "es", "cam", "de", "fr", "br", "ru", "cn",
    "buzz", "top", "xyz", "live", "site", "online", "fun",
}

# Patterns that indicate free robux lures
FREE_ROBUX_PATTERNS = re.compile(
    r'(free[_-]?robux|robux[_-]?free|robux[_-]?gen|rbx[_-]?free|'
    r'robux[_-]?hack|free[_-]?rbx|robuxgenerator|getrobux|earnrobux|'
    r'robux[_-]?gift|freerobux)',
    re.IGNORECASE
)

# URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
}


def get_tld_info(domain: str) -> dict:
    """Extract TLD components from a domain."""
    ext = tldextract.extract(domain)
    return {
        "subdomain": ext.subdomain,
        "domain_name": ext.domain,
        "tld": ext.suffix,
        "registered_domain": f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain,
    }


def classify_typosquat_technique(domain: str, url: str) -> str:
    """Classify the typosquatting technique used."""
    ext = tldextract.extract(domain)
    registered = f"{ext.domain}.{ext.suffix}".lower()
    domain_lower = domain.lower()
    domain_name = ext.domain.lower()

    # 1. ccTLD append: roblox.com.XX or roblox.XX (where roblox.com is mimicked)
    # Pattern: domain IS "roblox" with a non-.com TLD
    if domain_name == "roblox" and ext.suffix != "com":
        return "ccTLD_append"

    # Also catch roblox-com.XX pattern
    if domain_name == "roblox-com" or domain_name == "robloxcom":
        return "ccTLD_append"

    # 2. Protocol-in-domain: httpss-roblox.co, https-roblox.XX
    if re.match(r'https?s?[-_]', domain_name):
        return "protocol_in_domain"

    # 3. Hyphen insertion: www-roblox.XX, roblox-login.XX
    if re.search(r'(^www-robl|robl[o0]x-(?:com|login|verify|free|secure|support|account))', domain_lower):
        return "hyphen_insertion"

    # 4. Character substitution: robiox, r0blox, rob1ox, roblcx, rcblcx
    roblox_variants = [
        (r'r0bl[o0]x', "0 for o"),
        (r'rob[l1]ox', "1 for l"),
        (r'robi[o0]x', "i for l"),
        (r'robIox', "I for l"),
        (r'roblcx', "c for o"),
        (r'rcblcx', "c for o"),
        (r'robl0x', "0 for o"),
        (r'robiox', "i for l"),
        (r'roblax', "a for o"),
        (r'roblux', "u for o"),
        (r'roblxo', "letter swap"),
        (r'rolbox', "letter swap"),
        (r'roblo×', "homoglyph x"),
    ]
    for pattern, _ in roblox_variants:
        if re.search(pattern, domain_lower) and "roblox" not in domain_name:
            return "char_substitution"

    # 5. Character omission: rblox, roblx, roblo
    omission_patterns = [
        r'^r[bo]l[o0]x',   # rblox, rbolox
        r'^robl[o0][^x]',  # robloc, etc.
        r'^robx',           # robx
    ]
    for pat in omission_patterns:
        if re.search(pat, domain_name) and len(domain_name) < 6:
            return "char_omission"

    # 6. Homoglyph: using unicode lookalikes (rare in domain names but check)
    # Most homoglyphs are caught by char_substitution above

    # 7. Subdomain abuse: roblox.com.sketchysite.xyz — "roblox" appears in subdomain
    if ext.subdomain and re.search(r'robl[o0]x', ext.subdomain, re.IGNORECASE):
        if not re.search(r'robl[o0]x', domain_name, re.IGNORECASE):
            return "subdomain_abuse"

    # 8. Extra chars added: robloxc, robloxs, robloxia
    if re.match(r'^robl[o0]x.+', domain_name) and domain_name != "roblox":
        return "char_addition"

    # 9. Prefix addition: myroblox, theroblox, getroblox
    if re.match(r'^.+robl[o0]x$', domain_name) and domain_name != "roblox":
        return "prefix_addition"

    # If domain contains "roblox" exactly as a substring but with other stuff
    if "roblox" in domain_name and domain_name != "roblox":
        # Could be char_addition or prefix_addition - already caught above
        # Fallback to "compound" if both prefix and suffix
        if not domain_name.startswith("roblox") and not domain_name.endswith("roblox"):
            return "compound_modification"
        return "char_addition"

    return "none"


def classify_lure_type(url: str) -> str:
    """Classify the type of Roblox page being mimicked."""
    path = urlparse(url).path.lower() if "://" in url else ""
    query = urlparse(url).query.lower() if "://" in url else ""

    if "privateserverlinkcode" in query or "privateserver" in path:
        return "private_server_link"
    if "/users/" in path and "/profile" in path:
        return "profile_link"
    if "/games/" in path:
        return "game_link"
    if "/communities/" in path or "/groups/" in path:
        return "community_link"
    if "/upgrades/" in path or "robux" in path:
        return "robux_purchase"
    if "/login" in path or "/signin" in path or "/auth" in path:
        return "login_page"
    if "/catalog/" in path or "/marketplace" in path:
        return "catalog_link"
    if "/discover" in path:
        return "discover_link"

    return "other"


def classify_category(url: str, domain: str, typosquat_tech: str, lure_type: str) -> str:
    """Classify the primary phishing category."""
    domain_lower = domain.lower()
    url_lower = url.lower()

    # URL shortener abuse
    ext = tldextract.extract(domain)
    registered = f"{ext.domain}.{ext.suffix}".lower()
    if registered in URL_SHORTENERS:
        return "url_shortener"

    # Free robux scam
    if FREE_ROBUX_PATTERNS.search(url_lower) or FREE_ROBUX_PATTERNS.search(domain_lower):
        return "free_robux"

    # ccTLD abuse (roblox.XX with non-standard TLD)
    if typosquat_tech == "ccTLD_append":
        return "ccTLD_abuse"

    # Fake password reset (based on URL path patterns)
    if any(kw in url_lower for kw in ["reset", "password", "verify", "confirm", "security-alert"]):
        return "fake_reset"

    # Cookie theft (explicit references)
    if any(kw in url_lower for kw in ["cookie", "roblosecurity", "token"]):
        return "cookie_theft"

    # Malware download
    if any(kw in url_lower for kw in [".exe", ".msi", ".zip", ".rar", "download"]):
        return "malware_download"

    # Typosquatting (non-ccTLD variants)
    if typosquat_tech not in ("none", "ccTLD_append"):
        return "typosquatting"

    # Login page mimicry
    if lure_type == "login_page":
        return "credential_harvest"

    return "other"


def check_status(entry: dict) -> str:
    """Check if a URL is active or dead via HTTP HEAD request."""
    url = entry["url"]
    try:
        resp = requests.head(
            url,
            timeout=HEAD_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-research)"},
        )
        if resp.status_code < 400:
            return "active"
        elif resp.status_code in (403, 406, 503):
            # These might be behind Cloudflare/WAF — could still be active
            return "possibly_active"
        else:
            return "dead"
    except requests.exceptions.SSLError:
        return "ssl_error"
    except requests.exceptions.ConnectionError:
        return "dead"
    except requests.exceptions.Timeout:
        return "timeout"
    except Exception:
        return "dead"


def main():
    print("=" * 60)
    print("Roblox Phishing Categorizer — Phase 1C")
    print("=" * 60)

    # Load raw data
    with open(INPUT_FILE, "r") as f:
        entries = json.load(f)
    print(f"\nLoaded {len(entries)} entries from samples_raw.json")

    # --- Step 1: Categorize every entry ---
    print("\n[1/3] Categorizing entries...")

    for entry in entries:
        url = entry["url"]
        domain = entry["domain"]

        # TLD info
        tld_info = get_tld_info(domain)
        entry["tld"] = tld_info["tld"]
        entry["registered_domain"] = tld_info["registered_domain"]

        # Typosquatting technique
        entry["typosquat_technique"] = classify_typosquat_technique(domain, url)

        # Lure type
        entry["lure_type"] = classify_lure_type(url)

        # Category
        entry["category"] = classify_category(url, domain, entry["typosquat_technique"], entry["lure_type"])

    print("  Categorization complete.")

    # --- Step 2: Check active/dead status ---
    print(f"\n[2/3] Checking active/dead status ({len(entries)} URLs, {MAX_WORKERS} workers)...")
    print("  This may take a few minutes...")

    status_counts = Counter()
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_status, entry): entry for entry in entries}
        for future in as_completed(futures):
            entry = futures[future]
            try:
                status = future.result()
            except Exception:
                status = "error"
            entry["status"] = status
            status_counts[status] += 1
            completed += 1
            if completed % 200 == 0:
                print(f"  Checked {completed}/{len(entries)}...")

    print(f"  Status check complete: {completed} URLs checked")

    # --- Step 3: Link urlscan.io references ---
    print("\n[3/3] Linking urlscan.io references...")
    urlscan_count = sum(1 for e in entries if e.get("urlscan_ref"))
    print(f"  {urlscan_count} entries already have urlscan.io references")

    # --- Save output ---
    with open(OUTPUT_FILE, "w") as f:
        json.dump(entries, f, indent=2)
    print(f"\nSaved {len(entries)} entries to {OUTPUT_FILE}")

    # --- Generate Statistics ---
    print("\n" + "=" * 60)
    print("STATISTICS")
    print("=" * 60)

    # Category distribution
    cat_counts = Counter(e["category"] for e in entries)
    print(f"\n--- Category Distribution ---")
    for cat, count in cat_counts.most_common():
        pct = count / len(entries) * 100
        print(f"  {cat:25s} {count:5d}  ({pct:.1f}%)")

    # Typosquat technique distribution
    typo_counts = Counter(e["typosquat_technique"] for e in entries)
    print(f"\n--- Typosquat Technique Distribution ---")
    for tech, count in typo_counts.most_common():
        pct = count / len(entries) * 100
        print(f"  {tech:25s} {count:5d}  ({pct:.1f}%)")

    # Lure type distribution
    lure_counts = Counter(e["lure_type"] for e in entries)
    print(f"\n--- Lure Type Distribution ---")
    for lure, count in lure_counts.most_common():
        pct = count / len(entries) * 100
        print(f"  {lure:25s} {count:5d}  ({pct:.1f}%)")

    # TLD distribution (top 20)
    tld_counts = Counter(e["tld"] for e in entries)
    print(f"\n--- Top 20 TLDs ---")
    for tld, count in tld_counts.most_common(20):
        pct = count / len(entries) * 100
        print(f"  .{tld:24s} {count:5d}  ({pct:.1f}%)")

    # Status distribution
    print(f"\n--- Active/Dead Status ---")
    for status, count in status_counts.most_common():
        pct = count / len(entries) * 100
        print(f"  {status:25s} {count:5d}  ({pct:.1f}%)")

    # Source distribution
    source_counts = Counter()
    for e in entries:
        for src in e.get("sources", []):
            source_counts[src] += 1
    print(f"\n--- Source Distribution ---")
    for src, count in source_counts.most_common():
        print(f"  {src:30s} {count:5d}")

    # Cross-validated entries (multiple sources)
    multi_source = sum(1 for e in entries if len(e.get("sources", [])) > 1)
    print(f"\n  Cross-validated (multi-source): {multi_source}")

    print(f"\n{'=' * 60}")
    print(f"Total entries: {len(entries)}")
    print(f"Output: {OUTPUT_FILE}")
    print("Done!")


if __name__ == "__main__":
    main()
