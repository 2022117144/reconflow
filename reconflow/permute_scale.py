"""
reconflow.permute_scale
-------------------------
audits.generate_permutations() already does the basics: a fixed 23-word
list, DNS resolution only, capped at 300 candidates. Two real gaps for
using this at scale:

1. DNS-only resolution produces false positives on wildcard-DNS domains —
   literally any permutation "resolves" because everything resolves.
   This module adds an HTTP confirmation pass, reusing the same wildcard
   fingerprint logic reconflow.py already uses for live-host filtering.
2. The word list is hardcoded and small. This adds support for an
   external wordlist file (SecLists-style, one word per line), so
   candidate count scales with whatever list you point it at instead
   of being capped at ~23 words.
"""

import json
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def load_wordlist(path: str) -> list:
    words = [
        w.strip().lower()
        for w in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        if w.strip() and not w.startswith("#")
    ]
    return words


def _probe(host: str, timeout: int):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}", headers={"User-Agent": "reconflow-permute"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(2000)
                return {"host": host, "status": resp.status, "content_length": len(body)}
        except urllib.error.HTTPError as e:
            return {"host": host, "status": e.code, "content_length": 0}
        except Exception:
            continue
    return None


def generate_permutations_scaled(
    subdomains: list,
    domain: str,
    output_dir: Path,
    wordlist_path: str = None,
    max_candidates: int = 5000,
    threads: int = 30,
    timeout: int = 6,
) -> list:
    """
    Scaled-up version of audits.generate_permutations(): accepts an
    external wordlist and confirms candidates over HTTP (not just DNS),
    filtering out wildcard-DNS false positives the same way reconflow's
    live-host probing already does.
    """
    if wordlist_path:
        words = load_wordlist(wordlist_path)
        print(f"[*] Loaded {len(words)} words from {wordlist_path}")
    else:
        print("[!] No --perm-wordlist given — using the small built-in list. "
              "Pass a SecLists-style wordlist for real scale (e.g. "
              "SecLists/Discovery/DNS/subdomains-top1million-5000.txt)")
        from reconflow.audits import PERMUTATION_WORDS
        words = PERMUTATION_WORDS

    clean_subs = []
    for s in subdomains:
        s = s.lower().strip()
        if s.endswith(f".{domain}"):
            prefix = s[: -(len(domain) + 1)]
            if prefix and "." not in prefix:
                clean_subs.append(prefix)
    clean_subs = list(set(clean_subs))[:20]

    candidates = set()
    for word in words:
        candidates.add(f"{word}.{domain}")
    for base in clean_subs:
        for word in words:
            candidates.add(f"{word}-{base}.{domain}")
            candidates.add(f"{base}-{word}.{domain}")

    existing = set(subdomains)
    candidates = [c for c in candidates if c not in existing]
    if len(candidates) > max_candidates:
        print(f"[!] {len(candidates)} candidates generated, capping at {max_candidates} "
              f"(use --perm-max to raise this)")
        candidates = candidates[:max_candidates]

    print(f"[*] Probing {len(candidates)} permutation candidate(s) over HTTP "
          f"(this confirms real hosts, not just DNS resolution)...")

    raw_results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for result in executor.map(lambda h: _probe(h, timeout), candidates):
            if result:
                raw_results.append(result)

    # Wildcard filter: same logic as httpx probing in reconflow_v2.py —
    # if many "confirmed" hosts share one (status, content_length)
    # fingerprint, they're one catch-all page, not real distinct hosts.
    fingerprints = Counter((r["status"], r["content_length"]) for r in raw_results)
    common_fp = {
        fp for fp, count in fingerprints.items()
        if count > max(3, len(raw_results) * 0.3)
    }
    confirmed = [r for r in raw_results if (r["status"], r["content_length"]) not in common_fp]
    filtered_wildcard = len(raw_results) - len(confirmed)

    out_file = output_dir / "permutations_scaled.json"
    out_file.write_text(json.dumps(confirmed, indent=2), encoding="utf-8")

    print(f"[+] Confirmed {len(confirmed)} real permutation host(s) via HTTP "
          f"(filtered {filtered_wildcard} likely wildcard-DNS false positive(s))")
    return confirmed
