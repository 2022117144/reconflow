"""reconflow.diff - Differential change detection between scan runs."""

import json
import sys
from pathlib import Path
from . import history


def compare(old, new):
    """Compare two scan snapshots and return differences.

    Parameters:
        old (dict): Previous snapshot containing 'subdomains' and 'hosts'.
        new (dict): Recent snapshot containing 'subdomains' and 'hosts'.

    Returns:
        dict: Categorized differences (new_subdomains, removed_subdomains,
              new_live, gone_live, changed).
    """
    old_hosts = {
        h["url"]: h
        for h in (old.get("hosts") or [])
        if isinstance(h, dict) and "url" in h
    }
    new_hosts = {
        h["url"]: h
        for h in (new.get("hosts") or [])
        if isinstance(h, dict) and "url" in h
    }

    changed = {}
    for url in old_hosts.keys() & new_hosts.keys():
        o, n = old_hosts[url], new_hosts[url]
        diffs = {}
        if o.get("status_code") != n.get("status_code"):
            diffs["status_code"] = (o.get("status_code"), n.get("status_code"))
        if o.get("title") != n.get("title"):
            diffs["title"] = (o.get("title"), n.get("title"))
        old_tech = sorted(o.get("technologies") or [])
        new_tech = sorted(n.get("technologies") or [])
        if old_tech != new_tech:
            diffs["technologies"] = (o.get("technologies") or [], n.get("technologies") or [])
        if diffs:
            changed[url] = diffs

    old_subs = set(old.get("subdomains") or [])
    new_subs = set(new.get("subdomains") or [])

    return {
        "new_subdomains": sorted(new_subs - old_subs),
        "removed_subdomains": sorted(old_subs - new_subs),
        "new_live": sorted(new_hosts.keys() - old_hosts.keys()),
        "gone_live": sorted(old_hosts.keys() - new_hosts.keys()),
        "changed": changed,
    }


def format_diff(diff_result, old_id, new_id):
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
        for h in new_live:
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
        )
        print(output_text)

    sys.exit(1 if has_changes else 0)
