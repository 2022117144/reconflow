"""reconflow.diff - Differential change detection between scan runs."""

import json
import sys
from pathlib import Path
from urllib.parse import urlparse
from . import history


# Tags that flip between runs because of CDN/transport behavior, not app changes
IGNORED_TECH = {"HTTP/2", "HTTP/3", "HSTS"}


def _hostname(url):
    return (urlparse(url).hostname or url).lower()


def _by_host(hosts):
    """Map hostname -> host record. If a host answers on both schemes, prefer https."""
    result = {}
    for h in hosts or []:
        if not isinstance(h, dict) or "url" not in h:
            continue
        name = _hostname(h["url"])
        current = result.get(name)
        if current is None or (
            h["url"].startswith("https://") and not current["url"].startswith("https://")
        ):
            result[name] = h
    return result


def _meaningful_tech(tech):
    return {t for t in (tech or []) if t not in IGNORED_TECH}


def compare(old, new):
    """Compare two scan snapshots and return differences.

    Hosts are matched by hostname, so a scheme flip (http <-> https) is not
    reported as one host disappearing and another appearing.
    """
    old_hosts = _by_host(old.get("hosts"))
    new_hosts = _by_host(new.get("hosts"))

    changed = {}
    for name in old_hosts.keys() & new_hosts.keys():
        o, n = old_hosts[name], new_hosts[name]
        diffs = {}
        if o.get("status_code") != n.get("status_code"):
            diffs["status_code"] = (o.get("status_code"), n.get("status_code"))
        if o.get("title") != n.get("title"):
            diffs["title"] = (o.get("title"), n.get("title"))
        if _meaningful_tech(o.get("technologies")) != _meaningful_tech(n.get("technologies")):
            diffs["technologies"] = (o.get("technologies") or [], n.get("technologies") or [])
        if diffs:
            changed[n["url"]] = diffs

    old_subs = set(old.get("subdomains") or [])
    new_subs = set(new.get("subdomains") or [])
    return {
        "new_subdomains": sorted(new_subs - old_subs),
        "removed_subdomains": sorted(old_subs - new_subs),
        "new_live": sorted(new_hosts[h]["url"] for h in new_hosts.keys() - old_hosts.keys()),
        "gone_live": sorted(old_hosts[h]["url"] for h in old_hosts.keys() - new_hosts.keys()),
        "changed": changed,
    }


def format_diff(diff_result, old_id, new_id, new_data=None):
    """Render a human-readable comparison summary between two runs."""
    lines = [
        f"[*] Recon diff: {old_id} -> {new_id}",
        "=" * 60,
    ]

    new_subs = diff_result.get("new_subdomains", [])
    new_live = diff_result.get("new_live", [])
    changed = diff_result.get("changed", {})
    removed_subs = diff_result.get("removed_subdomains", [])
    gone_live = diff_result.get("gone_live", [])

    has_changes = any([new_subs, new_live, changed, removed_subs, gone_live])
    if not has_changes:
        lines.append("[+] No changes detected between scans.")
        return "\n".join(lines)

    if new_subs:
        lines.append(f"\n[+] NEW SUBDOMAINS ({len(new_subs)}):")
        for s in new_subs:
            lines.append(f"    + {s}")

    if new_live:
        lines.append(f"\n[+] NEWLY LIVE HOSTS ({len(new_live)}):")
        hosts_map = {}
        if new_data and isinstance(new_data, dict):
            hosts_map = {
                h["url"]: h
                for h in (new_data.get("hosts") or [])
                if isinstance(h, dict) and "url" in h
            }
        for h in new_live:
            meta = hosts_map.get(h)
            if meta:
                code = meta.get("status_code")
                title = meta.get("title")
                tech = meta.get("technologies") or []
                parts = []
                if code:
                    parts.append(f"[{code}]")
                if title:
                    parts.append(f"[{title}]")
                if tech:
                    tech_str = ", ".join(tech) if isinstance(tech, list) else str(tech)
                    parts.append(f"[{tech_str}]")
                detail = (" " + " ".join(parts)) if parts else ""
                lines.append(f"    + {h}{detail}")
            else:
                lines.append(f"    + {h}")

    if changed:
        lines.append(f"\n[*] CHANGED HOSTS ({len(changed)}):")
        for url, diffs in changed.items():
            lines.append(f"    ~ {url}")
            if "status_code" in diffs:
                o, n = diffs["status_code"]
                lines.append(f"        status: {o} -> {n}")
            if "title" in diffs:
                o, n = diffs["title"]
                lines.append(f"        title: '{o}' -> '{n}'")
            if "technologies" in diffs:
                o, n = diffs["technologies"]
                lines.append(f"        tech: {o} -> {n}")

    if removed_subs:
        lines.append(f"\n[-] Removed subdomains ({len(removed_subs)}) [informational]:")
        for s in removed_subs:
            lines.append(f"    - {s}")

    if gone_live:
        lines.append(f"\n[-] Inactive hosts ({len(gone_live)}) [informational]:")
        for h in gone_live:
            lines.append(f"    - {h}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def run(args):
    """Execute diff comparison for a domain between its latest two scan runs."""
    domain = getattr(args, "domain", None)
    if not domain:
        sys.exit("Error: Target domain is required.")

    output_dir = getattr(args, "output", "output") or "output"
    json_output = bool(getattr(args, "json_report", False) or getattr(args, "json", False))
    out_dir = Path(output_dir) / domain

    runs = history.list_runs(out_dir)
    if len(runs) < 2:
        if not runs:
            msg = f"[!] No scan history found for {domain} in {out_dir}. Run a scan first."
        else:
            msg = (
                f"[!] Only 1 scan run found for {domain} ({runs[0].name}). "
                "Need at least 2 runs to compare."
            )
        if json_output:
            print(json.dumps({"domain": domain, "error": msg, "runs_count": len(runs)}))
        else:
            print(msg)
        sys.exit(0)

    old_run = runs[-2]
    new_run = runs[-1]
    old_data = history.load_snapshot(old_run)
    new_data = history.load_snapshot(new_run)

    diff_result = compare(old_data, new_data)
    has_changes = any([
        diff_result["new_subdomains"],
        diff_result["new_live"],
        diff_result["changed"],
        diff_result["removed_subdomains"],
        diff_result["gone_live"],
    ])

    if json_output:
        payload = {
            "domain": domain,
            "old_run": old_data.get("run_id", old_run.name),
            "new_run": new_data.get("run_id", new_run.name),
            "has_changes": has_changes,
            **diff_result,
        }
        print(json.dumps(payload, indent=2))
    else:
        output_text = format_diff(
            diff_result,
            old_data.get("run_id", old_run.name),
            new_data.get("run_id", new_run.name),
            new_data=new_data,
        )
        print(output_text)

    sys.exit(1 if has_changes else 0)
