"""
reconflow.cve_correlate
-------------------------
Takes the technologies httpx already fingerprints on each live host
(via -tech-detect) and checks them against the NVD (National
Vulnerability Database) CVE API — free, no key required, but rate
limited to ~5 requests/30s without one, so this stage is intentionally
slow and should be run after --vuln, not instead of it. nuclei finds
exploitable instances; this just flags "this version has known CVEs,
worth a closer look" even when no nuclei template exists yet for it.
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# httpx's -tech-detect labels we don't bother querying — too generic,
# would return thousands of irrelevant CVEs.
SKIP_TECH = {"html5", "javascript", "css", "json", "cloudflare"}


def _query_nvd(keyword: str, timeout: int) -> list:
    url = f"{NVD_API}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=5"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "reconflow-cve-correlate"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            descriptions = cve.get("descriptions", [])
            summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    score = metrics[key][0]["cvssData"].get("baseScore")
                    break
            results.append({"cve_id": cve_id, "summary": summary[:200], "cvss_score": score})
        return results
    except urllib.error.HTTPError as e:
        if e.code == 403 or e.code == 429:
            print("[!] NVD rate limit hit — slowing down.")
            time.sleep(10)
        return []
    except Exception:
        return []


def correlate_cves(httpx_records, output_dir: Path, timeout: int = 15):
    """
    httpx_records: the list of parsed JSON records from the httpx probe
    stage (each may have a 'tech' field, a list of strings like
    'nginx:1.18.0' or just 'WordPress').
    """
    tech_versions = set()
    for rec in httpx_records or []:
        for tech in rec.get("tech", []):
            name = tech.split(":")[0].strip().lower()
            if name and name not in SKIP_TECH:
                tech_versions.add(tech.strip())

    if not tech_versions:
        print("[*] No specific technologies detected to correlate against CVEs "
              "(httpx -tech-detect data needed)")
        return []

    print(f"[*] Correlating {len(tech_versions)} detected technologies against NVD "
          f"(this is rate-limited, may take a while)...")

    findings = []
    for tech in sorted(tech_versions):
        cves = _query_nvd(tech, timeout)
        if cves:
            findings.append({"technology": tech, "cves": cves})
        time.sleep(6)  # stay under NVD's ~5 req/30s unauthenticated limit

    out_file = output_dir / "cve_correlation.json"
    out_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    total_cves = sum(len(f["cves"]) for f in findings)
    print(f"[+] Found {total_cves} potential CVE(s) across {len(findings)} technologies "
          f"— verify applicability manually, version strings can be approximate")
    return findings
