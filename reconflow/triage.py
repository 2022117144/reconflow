"""reconflow.triage - Triage state management for recon targets.

Allows hunters to mark hosts as --tested or --ignore on a per-domain basis,
so already-reviewed assets do not re-appear in differential scans.
"""

import datetime
import json
import sys
from pathlib import Path
from urllib.parse import urlparse


def normalize_target_host(target: str) -> str:
    """Normalize a target URL or host string to clean lowercase hostname."""
    if not target:
        return ""
    s = target.strip().lower()
    if "://" in s:
        s = urlparse(s).hostname or s
    elif "/" in s:
        s = s.split("/")[0]
    if ":" in s and not s.startswith("["):
        s = s.split(":")[0]
    return s.rstrip(".").strip()


def infer_domain(host: str, output_dir: Path = None) -> str:
    """Infer target domain from host name or existing folders in output directory."""
    clean = normalize_target_host(host)
    if not clean:
        return ""

    # Check if a folder in output matches a suffix of clean
    if output_dir and output_dir.exists():
        for d in output_dir.iterdir():
            if d.is_dir() and clean.endswith(d.name):
                return d.name

    parts = clean.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return clean


def get_triage_file(domain_dir: Path) -> Path:
    """Return path to triage.json inside domain directory."""
    return domain_dir / "triage.json"


def load_triage(domain_dir: Path) -> dict:
    """Load triage records for a domain."""
    triage_file = get_triage_file(domain_dir)
    if not triage_file.exists():
        return {"domain": domain_dir.name, "hosts": {}}
    try:
        data = json.loads(triage_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"domain": domain_dir.name, "hosts": {}}
        if "hosts" not in data or not isinstance(data["hosts"], dict):
            data["hosts"] = {}
        return data
    except Exception:
        return {"domain": domain_dir.name, "hosts": {}}


def save_triage(domain_dir: Path, data: dict):
    """Save triage records to triage.json atomically."""
    domain_dir.mkdir(parents=True, exist_ok=True)
    triage_file = get_triage_file(domain_dir)
    data["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    triage_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def mark_host(
    domain_dir: Path,
    host: str,
    status: str,
    notes: str = "",
) -> dict:
    """Mark a host as tested or ignore."""
    clean_host = normalize_target_host(host)
    if not clean_host:
        raise ValueError("Invalid host specified.")

    status = status.lower()
    if status not in ("tested", "ignore", "unmarked"):
        raise ValueError("Status must be 'tested' or 'ignore'.")

    triage_data = load_triage(domain_dir)
    if status == "unmarked":
        triage_data["hosts"].pop(clean_host, None)
    else:
        triage_data["hosts"][clean_host] = {
            "status": status,
            "marked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "notes": notes,
        }

    save_triage(domain_dir, triage_data)
    return triage_data["hosts"].get(clean_host, {})


def run(args):
    """Execute 'reconflow mark' CLI command."""
    host = getattr(args, "host", None)
    list_only = getattr(args, "list", False)
    output_dir = Path(getattr(args, "output", "output") or "output")
    domain = getattr(args, "domain", None)

    if not host and not list_only:
        sys.exit(
            "Error: Host to mark is required (e.g. reconflow mark admin.example.com --tested)."
        )

    if not domain and host:
        domain = infer_domain(host, output_dir=output_dir)

    if not domain:
        sys.exit("Error: Could not determine domain. Specify --domain <domain>.")

    domain_dir = output_dir / domain

    if list_only:
        triage_data = load_triage(domain_dir)
        hosts = triage_data.get("hosts", {})
        if not hosts:
            print(f"[*] No triaged hosts recorded for {domain}.")
            return
        print(f"[*] Triaged hosts for {domain} ({len(hosts)}):")
        for h, meta in sorted(hosts.items()):
            st = meta.get("status", "unknown")
            nt = f" - {meta['notes']}" if meta.get("notes") else ""
            print(f"    [{st.upper()}] {h}{nt}")
        return

    is_tested = getattr(args, "tested", False)
    is_ignore = getattr(args, "ignore", False)

    if not is_tested and not is_ignore:
        sys.exit("Error: Specify either --tested or --ignore (or --list to view).")

    status = "tested" if is_tested else "ignore"
    notes = getattr(args, "notes", "") or ""

    clean_host = normalize_target_host(host)
    mark_host(domain_dir, clean_host, status, notes=notes)
    print(f"[+] Marked {clean_host} as '{status}' for {domain} in {get_triage_file(domain_dir)}")
