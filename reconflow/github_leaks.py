"""
reconflow.github_leaks
------------------------
Searches GitHub's public code search for mentions of the target domain,
surfacing things like hardcoded internal URLs, leaked API keys referencing
the domain, or config files accidentally made public.

Needs a GitHub personal access token (no special scopes required — a
plain classic PAT or even a fine-grained token with no permissions works,
since this only hits public search). GitHub's code search API returns
403 for fully unauthenticated requests, so there's no token-less fallback
here — unlike the other modules, this one simply doesn't run without one.
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API_URL = "https://api.github.com/search/code"

# Queries that tend to catch real leaks without drowning in noise from
# every page that merely links to the target's marketing site.
QUERY_TEMPLATES = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" filename:.env',
    '"{domain}" filename:config',
]


def search_github_leaks(domain: str, output_dir: Path, token: str, timeout: int = 10):
    if not token:
        print("[!] --github-token not provided — GitHub requires authentication for "
              "code search, skipping this stage. Create a token (no scopes needed) at "
              "https://github.com/settings/tokens")
        return []

    print(f"[*] Searching public GitHub code for leaks referencing {domain}...")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "reconflow-github-leaks",
    }

    findings = []
    for template in QUERY_TEMPLATES:
        query = template.format(domain=domain)
        url = f"{API_URL}?q={urllib.parse.quote(query)}&per_page=10"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for item in data.get("items", []):
                findings.append({
                    "query": query,
                    "repo": item.get("repository", {}).get("full_name"),
                    "path": item.get("path"),
                    "url": item.get("html_url"),
                })
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print("[!] GitHub rate limit or token lacks search access — stopping early.")
                break
            if e.code == 422:
                continue  # query syntax GitHub rejected; skip it
        except Exception as e:
            print(f"[!] GitHub search failed for query {query!r}: {e}")

        time.sleep(2)  # code search is rate-limited to ~10 req/min even authenticated

    out_file = output_dir / "github_leaks.json"
    out_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[+] Found {len(findings)} potential GitHub reference(s) — manual review required, "
          f"these are leads, not confirmed leaks")
    return findings
