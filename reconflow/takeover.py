"""
reconflow.takeover
--------------------
Confirms subdomain takeovers. audits.audit_cname_records() already flags
subdomains whose CNAME points at a known third-party service — this module
takes that output a step further and actually fetches the page, checking
the response body against known "unclaimed resource" fingerprints.

A flagged-but-unconfirmed CNAME just means "dangling, worth checking by hand."
A confirmed one means the fingerprint matched — high-confidence, report-ready.
"""

import json
import urllib.error
import urllib.request
from pathlib import Path

# (provider substring in CNAME) -> (fingerprint text expected in response body)
# Conservative, well-established fingerprints only — false positives here
# would mean reporting a non-issue as a confirmed takeover.
TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "s3-website": "NoSuchBucket",
    "azurewebsites.net": "Error 404 - Web app not found",
    "zendesk.com": "Help Center Closed",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "fastly.net": "Fastly error: unknown domain",
    "pantheonsite.io": "The gods are wise",
    "ghost.io": "The thing you were looking for is no longer here",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
}


def _fetch(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "reconflow-takeover-check"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(500_000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        # Many of these fingerprints only show up on error pages (404/503) —
        # a non-2xx response is expected, not a reason to skip the check.
        try:
            return e.read(500_000).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    except Exception:
        return ""


def detect_subdomain_takeovers(cname_findings, output_dir: Path, timeout: int = 8):
    """
    cname_findings: the list returned by audits.audit_cname_records() —
    each item has 'subdomain', 'cname', 'provider', 'active_dns'.

    Only checks entries where active_dns is False or the provider itself
    returns an error page — those are the dangling, exploitable ones.
    """
    if not cname_findings:
        print("[*] No CNAME findings to check for takeover — run --cname-check first.")
        return []

    print(f"[*] Checking {len(cname_findings)} flagged CNAME(s) for confirmed takeover...")
    confirmed = []

    for entry in cname_findings:
        provider = entry.get("provider", "")
        subdomain = entry.get("subdomain")
        fingerprint = None
        for key, fp in TAKEOVER_FINGERPRINTS.items():
            if key.strip(".") in provider or provider in key:
                fingerprint = fp
                break
        if not fingerprint or not subdomain:
            continue

        body = _fetch(f"http://{subdomain}", timeout)
        if not body:
            body = _fetch(f"https://{subdomain}", timeout)

        if fingerprint.lower() in body.lower():
            confirmed.append({
                "subdomain": subdomain,
                "cname": entry.get("cname"),
                "provider": entry.get("provider"),
                "fingerprint_matched": fingerprint,
                "confidence": "high",
            })

    out_file = output_dir / "takeover_confirmed.json"
    out_file.write_text(json.dumps(confirmed, indent=2), encoding="utf-8")

    if confirmed:
        print(f"[+] CONFIRMED {len(confirmed)} subdomain takeover(s) — see takeover_confirmed.json")
    else:
        print("[+] No confirmed takeovers (dangling CNAMEs may still be worth manual review)")
    return confirmed
