#!/usr/bin/env python3
"""reconflow - chain subdomain discovery and live host probing."""

import argparse
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def check_tools(tools):
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        sys.exit(f"Missing tools: {', '.join(missing)}. See README for install steps.")


def run(cmd):
    return subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )


def find_subdomains(domain, out_file):
    print(f"[*] Finding subdomains for {domain}...")
    result = run(["subfinder", "-d", domain, "-silent"])
    subs = sorted(set(result.stdout.split()))
    out_file.write_text("\n".join(subs) + "\n", encoding="utf-8")
    print(f"[+] Found {len(subs)} subdomains")
    return subs


def probe_hosts(subs_file, out_file):
    print("[*] Probing for live hosts (this can take a while on big targets)...")
    result = run(["httpx", "-l", str(subs_file), "-silent",
                  "-status-code", "-title", "-tech-detect"])
    lines = [l for l in result.stdout.splitlines() if l.strip()]
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] {len(lines)} hosts are alive")
    return lines


def write_report(domain, subs, live, out_dir):
    report = out_dir / "report.md"
    report.write_text(
        f"# reconflow report: {domain}\n\n"
        f"Generated: {datetime.now():%Y-%m-%d %H:%M}\n\n"
        f"- Subdomains found: {len(subs)}\n"
        f"- Live hosts: {len(live)}\n\n"
        f"## Live hosts\n\n```\n" + "\n".join(live) + "\n```\n",
        encoding="utf-8",
    )
    print(f"[+] Report saved to {report}")


def main():
    parser = argparse.ArgumentParser(
        description="reconflow: subdomain discovery + live host probing in one command")
    parser.add_argument("-d", "--domain", required=True, help="target domain (must be in scope!)")
    parser.add_argument("-o", "--output", default="output", help="output folder (default: output)")
    args = parser.parse_args()

    check_tools(["subfinder", "httpx"])

    out_dir = Path(args.output) / args.domain
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        subs = find_subdomains(args.domain, out_dir / "subdomains.txt")
        live = probe_hosts(out_dir / "subdomains.txt", out_dir / "live.txt")
        write_report(args.domain, subs, live, out_dir)
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted. Partial results (if any) are in " + str(out_dir))


if __name__ == "__main__":
    main()