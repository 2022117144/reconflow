#!/usr/bin/env python3
"""
reconflow v2 — subdomain discovery, live host probing, port scanning,
URL/param collection, vuln scanning (nuclei), and JS secret scanning,
chained into one command with a unified HTML report.

Keeps every v1 flag working. New stages are opt-in so existing users
and CI don't suddenly need naabu/nuclei/gau installed.

  Use responsibly. Only scan domains you own or that are explicitly
  in scope for a program you are authorized to test.
"""

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

from reconflow import modules, notify, report


def run_subfinder(domain: str, output_dir: Path):
    if shutil.which("subfinder") is None:
        sys.exit("[!] subfinder not found on PATH. Install it from "
                 "https://github.com/projectdiscovery/subfinder")
    print(f"[*] Finding subdomains for {domain}...")
    proc = subprocess.run(["subfinder", "-d", domain, "-silent"],
                          capture_output=True, text=True)
    subs = sorted({s.strip() for s in proc.stdout.splitlines() if s.strip()})
    (output_dir / "subdomains.txt").write_text("\n".join(subs), encoding="utf-8")
    print(f"[+] Found {len(subs)} subdomains")
    return subs


def run_httpx(subdomains, output_dir: Path, threads=None, timeout=None,
              keep_wildcard=False):
    if shutil.which("httpx") is None:
        sys.exit("[!] httpx not found on PATH. Install it from "
                 "https://github.com/projectdiscovery/httpx")
    print("[*] Probing for live hosts...")
    cmd = ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect"]
    if threads:
        cmd += ["-threads", str(threads)]
    if timeout:
        cmd += ["-timeout", str(timeout)]

    proc = subprocess.run(cmd, input="\n".join(subdomains), capture_output=True, text=True)
    records = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not keep_wildcard and records:
        # Wildcard DNS filter: if many hosts share one (status_code, content-length)
        # fingerprint, they're almost certainly the same catch-all page.
        fingerprints = Counter((r.get("status_code"), r.get("content_length")) for r in records)
        common_fp = {fp for fp, count in fingerprints.items()
                     if count > max(3, len(records) * 0.3)}
        before = len(records)
        records = [r for r in records
                   if (r.get("status_code"), r.get("content_length")) not in common_fp]
        filtered = before - len(records)
        if filtered:
            print(f"[+] Filtered {filtered} likely wildcard DNS false positives "
                  f"(use --keep-wildcard to disable)")

    live_hosts = [r.get("url") or r.get("input") for r in records]
    (output_dir / "live.txt").write_text("\n".join(live_hosts), encoding="utf-8")
    print(f"[+] {len(live_hosts)} hosts are alive")
    return live_hosts, records


def build_markdown_report(domain, output_dir: Path, subdomains, live_hosts, extra_lines=None):
    lines = [
        f"# reconflow report — {domain}", "",
        f"- Subdomains found: **{len(subdomains)}**",
        f"- Live hosts: **{len(live_hosts)}**",
    ]
    if extra_lines:
        lines += extra_lines
    (output_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="reconflow — all-in-one bug bounty recon")
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("-o", "--output", default="output")
    ap.add_argument("--threads", type=int)
    ap.add_argument("--timeout", type=int)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep-wildcard", action="store_true")
    ap.add_argument("--screenshots", action="store_true")

    # new stages — all opt-in
    ap.add_argument("--ports", action="store_true", help="port scan live hosts with naabu")
    ap.add_argument("--top-ports", type=int, default=100)
    ap.add_argument("--urls", action="store_true",
                    help="collect historical URLs + params with gau")
    ap.add_argument("--vuln", action="store_true", help="run nuclei against live hosts")
    ap.add_argument("--severity", default="medium,high,critical",
                     help="nuclei severity filter (comma-separated)")
    ap.add_argument("--secrets", action="store_true", help="scan JS files for leaked secrets")
    ap.add_argument("--full", action="store_true",
                    help="shortcut for --ports --urls --vuln --secrets --html")
    ap.add_argument("--html", action="store_true", help="also build an HTML report")
    ap.add_argument("--notify", metavar="WEBHOOK_URL",
                    help="Discord/Slack webhook to ping when done")

    args = ap.parse_args()
    if args.full:
        args.ports = args.urls = args.vuln = args.secrets = args.html = True

    output_dir = Path(args.output) / args.domain
    output_dir.mkdir(parents=True, exist_ok=True)

    subdomains = run_subfinder(args.domain, output_dir)
    live_hosts, httpx_records = run_httpx(
        subdomains, output_dir, args.threads, args.timeout, args.keep_wildcard
    )

    ports_by_host, urls, params, vuln_findings, secret_findings = {}, [], [], [], []

    if args.ports and live_hosts:
        ports_by_host = modules.port_scan(live_hosts, output_dir, args.top_ports)

    if args.urls:
        urls, params = modules.url_collect(args.domain, output_dir)

    if args.vuln and live_hosts:
        vuln_findings = modules.vuln_scan(live_hosts, output_dir, args.severity)

    if args.secrets:
        js_source = urls if urls else live_hosts
        secret_findings = modules.secret_scan(js_source, output_dir)

    if args.screenshots:
        if shutil.which("gowitness") is None:
            print("[!] gowitness not found on PATH — skipping screenshots.")
        else:
            shots_dir = output_dir / "screenshots"
            shots_dir.mkdir(exist_ok=True)
            subprocess.run(["gowitness", "file", "-f", str(output_dir / "live.txt"),
                            "-P", str(shots_dir)], capture_output=True)
            print(f"[+] Screenshots saved to {shots_dir}")

    extra_md = []
    if ports_by_host:
        extra_md.append(f"- Hosts with open ports: **{len(ports_by_host)}**")
    if urls:
        extra_md.append(f"- URLs collected: **{len(urls)}** ({len(params)} unique params)")
    if vuln_findings:
        extra_md.append(f"- Vulnerability findings: **{len(vuln_findings)}**")
    if secret_findings:
        extra_md.append(f"- Potential secrets found: **{len(secret_findings)}**")

    build_markdown_report(args.domain, output_dir, subdomains, live_hosts, extra_md)

    if args.json:
        (output_dir / "report.json").write_text(json.dumps({
            "domain": args.domain,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "ports": ports_by_host,
            "urls": urls,
            "params": params,
            "vulnerabilities": vuln_findings,
            "secrets": secret_findings,
        }, indent=2), encoding="utf-8")

    if args.html:
        report.build_html_report(
            args.domain, output_dir, subdomains, live_hosts,
            ports_by_host, vuln_findings, secret_findings, len(urls), len(params),
        )

    if args.notify:
        notify.send_webhook(args.notify, args.domain, {
            "Subdomains": len(subdomains),
            "Live hosts": len(live_hosts),
            "Vuln findings": len(vuln_findings),
            "Potential secrets": len(secret_findings),
        })

    print(f"[+] Report saved to {output_dir / 'report.md'}")


if __name__ == "__main__":
    main()
