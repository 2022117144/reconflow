#!/usr/bin/env python3
"""
reconflow v2 — subdomain discovery, live host probing, port scanning,
URL/param collection, vuln scanning (nuclei), JS secret scanning, and
endpoint fuzzing (ffuf), chained with unified HTML reports and resumable runs.

Keeps every v1 flag working. New stages are opt-in so existing users
and CI don't suddenly need naabu/nuclei/gau/ffuf installed.

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

from reconflow import config, modules, notify, report, state


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
    ap.add_argument("-c", "--config", help="path to custom config file (e.g., reconflow.yaml)")
    ap.add_argument("--resume", action="store_true", help="resume an interrupted scan")
    ap.add_argument("--threads", type=int)
    ap.add_argument("--timeout", type=int)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep-wildcard", action="store_true")
    ap.add_argument("--screenshots", action="store_true")

    # new stages — all opt-in
    ap.add_argument("--ports", action="store_true", help="port scan live hosts with naabu")
    ap.add_argument("--top-ports", type=int)
    ap.add_argument("--urls", action="store_true",
                    help="collect historical URLs + params with gau")
    ap.add_argument("--vuln", action="store_true", help="run nuclei against live hosts")
    ap.add_argument("--severity", help="nuclei severity filter (comma-separated)")
    ap.add_argument("--secrets", action="store_true", help="scan JS files for leaked secrets")
    ap.add_argument("--fuzz", action="store_true", help="fuzz endpoints on live hosts with ffuf")
    ap.add_argument("--wordlist", help="wordlist for ffuf fuzzing")
    ap.add_argument("--full", action="store_true",
                    help="shortcut for --ports --urls --vuln --secrets --fuzz --html")
    ap.add_argument("--html", action="store_true", help="also build an HTML report")
    ap.add_argument("--notify", metavar="WEBHOOK_URL",
                    help="Discord/Slack webhook to ping when done")

    args = ap.parse_args()

    # Load configuration file (reconflow.yaml / json)
    cfg = config.load_config(args.config)
    cfg_defaults = cfg.get("defaults", {})

    # Apply configuration defaults if CLI arguments were not provided
    if args.threads is None:
        args.threads = cfg_defaults.get("threads")
    if args.timeout is None:
        args.timeout = cfg_defaults.get("timeout")
    if args.top_ports is None:
        args.top_ports = cfg_defaults.get("top_ports", 100)
    if not args.severity:
        args.severity = cfg_defaults.get("severity", "medium,high,critical")
    if not args.notify:
        args.notify = cfg.get("notify", {}).get("webhook_url")

    if args.full:
        args.ports = args.urls = args.vuln = args.secrets = args.fuzz = args.html = True

    output_dir = Path(args.output) / args.domain
    output_dir.mkdir(parents=True, exist_ok=True)

    sm = state.StateManager(output_dir, args.domain, resume=args.resume)

    # Stage 1: Subdomains
    if sm.is_completed("subdomains") and (output_dir / "subdomains.txt").exists():
        print(f"[*] Resuming: loading subdomains from {output_dir / 'subdomains.txt'}")
        subdomains = [line.strip() for line in (output_dir / "subdomains.txt")
                      .read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        subdomains = run_subfinder(args.domain, output_dir)
        sm.mark_completed("subdomains", {"count": len(subdomains)})

    # Stage 2: Live Hosts
    if sm.is_completed("live_hosts") and (output_dir / "live.txt").exists():
        print(f"[*] Resuming: loading live hosts from {output_dir / 'live.txt'}")
        live_hosts = [line.strip() for line in (output_dir / "live.txt")
                      .read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        live_hosts, _ = run_httpx(
            subdomains, output_dir, args.threads, args.timeout, args.keep_wildcard
        )
        sm.mark_completed("live_hosts", {"count": len(live_hosts)})

    ports_by_host, urls, params = {}, [], []
    vuln_findings, secret_findings, fuzz_findings = [], [], []

    # Stage 3: Port Scan
    if args.ports and live_hosts:
        if sm.is_completed("ports") and (output_dir / "ports.json").exists():
            print(f"[*] Resuming: loading ports from {output_dir / 'ports.json'}")
            try:
                ports_by_host = json.loads((output_dir / "ports.json").read_text(encoding="utf-8"))
            except Exception:
                ports_by_host = modules.port_scan(live_hosts, output_dir, args.top_ports)
        else:
            ports_by_host = modules.port_scan(live_hosts, output_dir, args.top_ports)
            sm.mark_completed("ports", {"hosts_with_ports": len(ports_by_host)})

    # Stage 4: Historical URLs & Params
    if args.urls:
        if sm.is_completed("urls") and (output_dir / "urls.txt").exists():
            print(f"[*] Resuming: loading URLs from {output_dir / 'urls.txt'}")
            urls = [line.strip() for line in (output_dir / "urls.txt")
                    .read_text(encoding="utf-8").splitlines() if line.strip()]
            if (output_dir / "params.txt").exists():
                params = [line.strip() for line in (output_dir / "params.txt")
                          .read_text(encoding="utf-8").splitlines() if line.strip()]
        else:
            urls, params = modules.url_collect(args.domain, output_dir)
            sm.mark_completed("urls", {"urls_count": len(urls), "params_count": len(params)})

    # Stage 5: Vulnerability Scan
    if args.vuln and live_hosts:
        if sm.is_completed("vuln") and (output_dir / "vulns.json").exists():
            print(f"[*] Resuming: loading vulnerabilities from {output_dir / 'vulns.json'}")
            try:
                lines = (output_dir / "vulns.json").read_text(encoding="utf-8").splitlines()
                vuln_findings = [json.loads(line) for line in lines if line.strip()]
            except Exception:
                vuln_findings = modules.vuln_scan(live_hosts, output_dir, args.severity)
        else:
            vuln_findings = modules.vuln_scan(live_hosts, output_dir, args.severity)
            sm.mark_completed("vuln", {"findings_count": len(vuln_findings)})

    # Stage 6: Secret Scan
    if args.secrets:
        if sm.is_completed("secrets") and (output_dir / "secrets.json").exists():
            print(f"[*] Resuming: loading secrets from {output_dir / 'secrets.json'}")
            try:
                secret_findings = json.loads(
                    (output_dir / "secrets.json").read_text(encoding="utf-8")
                )
            except Exception:
                js_source = urls if urls else live_hosts
                secret_findings = modules.secret_scan(js_source, output_dir)
        else:
            js_source = urls if urls else live_hosts
            secret_findings = modules.secret_scan(js_source, output_dir)
            sm.mark_completed("secrets", {"secrets_count": len(secret_findings)})

    # Stage 7: Directory Fuzzing (ffuf)
    if args.fuzz and live_hosts:
        if sm.is_completed("fuzz") and (output_dir / "fuzz.json").exists():
            print(f"[*] Resuming: loading fuzzing results from {output_dir / 'fuzz.json'}")
            try:
                fuzz_findings = json.loads(
                    (output_dir / "fuzz.json").read_text(encoding="utf-8")
                )
            except Exception:
                fuzz_findings = modules.dir_fuzz(live_hosts, output_dir, args.wordlist)
        else:
            fuzz_findings = modules.dir_fuzz(live_hosts, output_dir, args.wordlist)
            sm.mark_completed("fuzz", {"endpoints_count": len(fuzz_findings)})

    # Stage 8: Screenshots (gowitness)
    if args.screenshots:
        if shutil.which("gowitness") is None:
            print("[!] gowitness not found on PATH — skipping screenshots.")
        else:
            shots_dir = output_dir / "screenshots"
            shots_dir.mkdir(exist_ok=True)
            subprocess.run(["gowitness", "file", "-f", str(output_dir / "live.txt"),
                            "-P", str(shots_dir)], capture_output=True)
            print(f"[+] Screenshots saved to {shots_dir}")
            sm.mark_completed("screenshots")

    extra_md = []
    if ports_by_host:
        extra_md.append(f"- Hosts with open ports: **{len(ports_by_host)}**")
    if urls:
        extra_md.append(f"- URLs collected: **{len(urls)}** ({len(params)} unique params)")
    if vuln_findings:
        extra_md.append(f"- Vulnerability findings: **{len(vuln_findings)}**")
    if secret_findings:
        extra_md.append(f"- Potential secrets found: **{len(secret_findings)}**")
    if fuzz_findings:
        extra_md.append(f"- Discovered endpoints: **{len(fuzz_findings)}**")

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
            "endpoints": fuzz_findings,
        }, indent=2), encoding="utf-8")

    if args.html:
        report.build_html_report(
            args.domain, output_dir, subdomains, live_hosts,
            ports_by_host, vuln_findings, secret_findings, fuzz_findings,
            len(urls), len(params),
        )

    if args.notify:
        notify.send_webhook(args.notify, args.domain, {
            "Subdomains": len(subdomains),
            "Live hosts": len(live_hosts),
            "Vuln findings": len(vuln_findings),
            "Potential secrets": len(secret_findings),
            "Endpoints": len(fuzz_findings),
        })

    print(f"[+] Report saved to {output_dir / 'report.md'}")


if __name__ == "__main__":
    main()
