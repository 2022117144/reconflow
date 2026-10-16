"""
reconflow.modules
------------------
Wrappers around external recon tools, plus the pure-Python secret scanner.
Every function is defensive: if the underlying binary isn't on PATH, it
prints a clear warning and returns an empty result instead of crashing
the whole run, so `reconflow.py` can keep going with whatever tools
the user actually has installed.
"""

import json
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path


def _tool_missing(name: str) -> bool:
    if shutil.which(name) is None:
        print(f"[!] '{name}' not found on PATH — skipping this stage. "
              f"Install it to enable this feature.")
        return True
    return False


# ---------------------------------------------------------------- ports ----

def port_scan(live_hosts, output_dir: Path, top_ports: int = 100, rate: int = 1000):
    """Run naabu against a list of hosts (hostnames or IPs, no scheme)."""
    if _tool_missing("naabu"):
        return {}

    hosts_file = output_dir / "hosts_for_portscan.txt"
    clean_hosts = sorted({h.split("://", 1)[-1].split("/", 1)[0] for h in live_hosts})
    hosts_file.write_text("\n".join(clean_hosts), encoding="utf-8")

    out_file = output_dir / "ports.json"
    cmd = [
        "naabu", "-list", str(hosts_file),
        "-top-ports", str(top_ports),
        "-rate", str(rate),
        "-json", "-o", str(out_file), "-silent",
    ]
    print(f"[*] Port scanning {len(clean_hosts)} hosts (top {top_ports} ports)...")
    subprocess.run(cmd, capture_output=True, text=True)

    results = {}
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = rec.get("host") or rec.get("ip")
            port = rec.get("port")
            if host and port:
                results.setdefault(host, []).append(port)
    print(f"[+] Open ports found on {len(results)} hosts")
    return results


# ----------------------------------------------------------- url/param ----

PARAM_RE = re.compile(r"[?&]([a-zA-Z0-9_\[\]]+)=")


def url_collect(domain: str, output_dir: Path):
    """Pull historical URLs via gau and split out unique query parameters."""
    if _tool_missing("gau"):
        return [], []

    print(f"[*] Collecting historical URLs for {domain}...")
    proc = subprocess.run(["gau", "--subs", domain], capture_output=True, text=True)
    urls = sorted({u.strip() for u in proc.stdout.splitlines() if u.strip()})

    (output_dir / "urls.txt").write_text("\n".join(urls), encoding="utf-8")

    params = sorted({m.group(1) for u in urls for m in PARAM_RE.finditer(u)})
    (output_dir / "params.txt").write_text("\n".join(params), encoding="utf-8")

    print(f"[+] Collected {len(urls)} URLs, {len(params)} unique parameters")
    return urls, params


# -------------------------------------------------------------- nuclei ----

def vuln_scan(live_hosts, output_dir: Path, severity: str = "medium,high,critical",
              rate_limit: int = 150):
    """Run nuclei against live hosts, scoped to a minimum severity by default
    so a first run doesn't drown you in 'info' noise."""
    if _tool_missing("nuclei"):
        return []

    hosts_file = output_dir / "hosts_for_vulnscan.txt"
    hosts_file.write_text("\n".join(live_hosts), encoding="utf-8")

    out_file = output_dir / "vulns.json"
    cmd = [
        "nuclei", "-list", str(hosts_file),
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-jsonl", "-o", str(out_file), "-silent",
    ]
    print(f"[*] Running nuclei (severity: {severity}) against {len(live_hosts)} hosts...")
    subprocess.run(cmd, capture_output=True, text=True)

    findings = []
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    print(f"[+] nuclei flagged {len(findings)} findings")
    return findings


# ------------------------------------------------------------- secrets ----

# Intentionally conservative patterns to keep false positives manageable.
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Key": re.compile(
        r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][a-z0-9_\-]{16,45}['\"]"
    ),
    "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"),
    "JWT": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"),
    "Firebase URL": re.compile(r"[a-z0-9.-]+\.firebaseio\.com"),
}


def _extract_js_urls(urls):
    return [u for u in urls if u.split("?")[0].endswith(".js")]


def secret_scan(urls, output_dir: Path, timeout: int = 8):
    """Fetch JS files from a URL list and regex-scan them for leaked secrets."""
    js_urls = _extract_js_urls(urls)
    if not js_urls:
        print("[*] No .js URLs to scan for secrets")
        return []

    print(f"[*] Scanning {len(js_urls)} JS files for leaked secrets...")
    findings = []
    for url in js_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "reconflow"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(2_000_000).decode("utf-8", errors="ignore")
        except Exception:
            continue
        for label, pattern in SECRET_PATTERNS.items():
            for match in pattern.findall(body):
                findings.append({"url": url, "type": label, "match": match[:80]})

    out_file = output_dir / "secrets.json"
    out_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    suffix = " — review secrets.json" if findings else ""
    print(f"[+] Found {len(findings)} potential secret(s){suffix}")
    return findings


# ------------------------------------------------------------- fuzzing ----

DEFAULT_WORDLIST = Path(__file__).resolve().parent / "wordlists" / "common.txt"


def dir_fuzz(live_hosts, output_dir: Path, wordlist: str = None, threads: int = 40,
             max_hosts: int = 15):
    """Run ffuf against live hosts to discover common files, portals, and endpoints."""
    if _tool_missing("ffuf"):
        return []

    wl_path = Path(wordlist) if wordlist else DEFAULT_WORDLIST
    if not wl_path.exists():
        print(f"[!] Wordlist '{wl_path}' not found — skipping fuzzing.")
        return []

    hosts_to_scan = live_hosts[:max_hosts]
    print(f"[*] Fuzzing endpoints across {len(hosts_to_scan)} live hosts with ffuf...")

    all_findings = []
    for host in hosts_to_scan:
        clean_host = host.rstrip("/")
        tmp_out = output_dir / f"ffuf_{len(all_findings)}.json"
        cmd = [
            "ffuf", "-u", f"{clean_host}/FUZZ",
            "-w", str(wl_path),
            "-mc", "200,204,301,302,307,401,403",
            "-t", str(threads),
            "-of", "json", "-o", str(tmp_out), "-s",
        ]
        subprocess.run(cmd, capture_output=True, text=True)
        if tmp_out.exists():
            try:
                data = json.loads(tmp_out.read_text(encoding="utf-8"))
                for res in data.get("results", []):
                    all_findings.append({
                        "url": res.get("url"),
                        "status": res.get("status"),
                        "length": res.get("length"),
                    })
                tmp_out.unlink(missing_ok=True)
            except Exception:
                pass

    out_file = output_dir / "fuzz.json"
    out_file.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")
    print(f"[+] ffuf discovered {len(all_findings)} endpoints")
    return all_findings

