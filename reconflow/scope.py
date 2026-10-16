"""
reconflow.scope
-----------------
Parses a bug bounty program's scope and filters discovered subdomains
against it, so you don't accidentally report (or get flagged for testing)
something out of scope.

Supports two input formats:
  1. HackerOne-style JSON export: a list of objects with
     "asset_identifier", "asset_type", "eligible_for_bounty" /
     "eligible_for_submission" / "instruction" containing "out of scope"
  2. Plain text, one entry per line:
       example.com
       *.example.com
       !excluded.example.com      <- leading "!" means explicitly out of scope
       # comments and blank lines ignored
"""

import fnmatch
import json
from pathlib import Path


def _normalize(asset: str) -> str:
    return asset.strip().lower().lstrip("*.")


def load_scope(path: str):
    """Returns {'in_scope': [...], 'out_of_scope': [...]} of glob-style patterns."""
    text = Path(path).read_text(encoding="utf-8")
    in_scope, out_of_scope = [], []

    stripped = text.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            items = data if isinstance(data, list) else data.get("scope", data.get("targets", []))
            for item in items:
                if not isinstance(item, dict):
                    continue
                asset = item.get("asset_identifier") or item.get("target") or item.get("identifier")
                if not asset:
                    continue
                asset_type = (item.get("asset_type") or "").upper()
                if asset_type and "URL" not in asset_type and "DOMAIN" not in asset_type \
                        and "WILDCARD" not in asset_type and "OTHER" not in asset_type:
                    continue  # skip mobile apps, source code repos, etc.
                eligible = item.get(
                    "eligible_for_submission",
                    item.get("eligible_for_bounty", True),
                )
                (in_scope if eligible else out_of_scope).append(_normalize(asset))
            return {"in_scope": in_scope, "out_of_scope": out_of_scope}
        except json.JSONDecodeError:
            pass  # fall through to plain-text parsing

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            out_of_scope.append(_normalize(line[1:]))
        else:
            in_scope.append(_normalize(line))

    return {"in_scope": in_scope, "out_of_scope": out_of_scope}


def _matches_any(host: str, patterns) -> bool:
    host = host.lower()
    for pattern in patterns:
        if host == pattern or host.endswith(f".{pattern}") or fnmatch.fnmatch(host, f"*{pattern}*"):
            return True
    return False


def filter_in_scope(subdomains, scope: dict, output_dir: Path = None):
    """Returns (in_scope_list, out_of_scope_list). Out-of-scope rules win ties."""
    in_scope_patterns = scope.get("in_scope", [])
    out_of_scope_patterns = scope.get("out_of_scope", [])

    kept, dropped = [], []
    for host in subdomains:
        clean = host.split("://", 1)[-1].split("/", 1)[0]
        if _matches_any(clean, out_of_scope_patterns):
            dropped.append(host)
        elif not in_scope_patterns or _matches_any(clean, in_scope_patterns):
            kept.append(host)
        else:
            dropped.append(host)

    if output_dir:
        (output_dir / "scope_filtered_out.txt").write_text("\n".join(dropped), encoding="utf-8")

    print(f"[+] Scope filter: {len(kept)} in-scope, {len(dropped)} excluded")
    return kept, dropped
