"""
reconflow.audits
-----------------
Defensive asset auditing modules:
1. Cloud Asset Identification (AWS S3, GCP Storage, Azure Blob)
2. Network ASN & IP range mapping via RDAP
3. HTTP Header & CORS policy audit
4. DNS CNAME validation for dangling provider records
"""

import json
import re
import socket
import urllib.request
from pathlib import Path

# Regular expressions for public cloud storage endpoints
CLOUD_PATTERNS = {
    "AWS S3": re.compile(
        r"(?:https?://)?([a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"
        r"|s3\.amazonaws\.com/[a-z0-9.-]+)",
        re.IGNORECASE,
    ),
    "Google Cloud Storage": re.compile(
        r"(?:https?://)?(storage\.googleapis\.com/[a-z0-9_.-]+"
        r"|[a-z0-9_.-]+\.storage\.googleapis\.com)",
        re.IGNORECASE,
    ),
    "Azure Blob Storage": re.compile(
        r"(?:https?://)?([a-z0-9.-]+\.blob\.core\.windows\.net(?:/[a-z0-9.-]+)?)",
        re.IGNORECASE,
    ),
    "DigitalOcean Space": re.compile(
        r"(?:https?://)?([a-z0-9.-]+\.[a-z0-9-]+\.digitaloceanspaces\.com)",
        re.IGNORECASE,
    ),
}

# Known third-party service provider CNAME signatures
KNOWN_SERVICE_PROVIDERS = [
    ".github.io",
    ".herokuapp.com",
    ".s3-website",
    ".s3.amazonaws.com",
    ".azurewebsites.net",
    ".zendesk.com",
    ".myshopify.com",
    ".fastly.net",
    ".pantheonsite.io",
    ".ghost.io",
    ".surge.sh",
    ".bitbucket.io",
]


def detect_cloud_assets(urls, live_hosts, output_dir: Path) -> list:
    """Identify cloud storage bucket references mentioned in discovered URLs and hosts."""
    print("[*] Scanning discovered assets for cloud storage bucket references...")
    candidates = set(urls) | set(live_hosts)
    found_assets = {}

    for item in candidates:
        for provider, pattern in CLOUD_PATTERNS.items():
            matches = pattern.findall(item)
            for m in matches:
                clean = m.split("?")[0].rstrip("/")
                if clean not in found_assets:
                    found_assets[clean] = {"provider": provider, "source": item}

    results = [{"asset": k, **v} for k, v in found_assets.items()]
    out_file = output_dir / "cloud_assets.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[+] Identified {len(results)} cloud storage reference(s)")
    return results


def lookup_asn_ranges(live_hosts, output_dir: Path, timeout: int = 5) -> dict:
    """Resolve IPs for live hosts and query ASN/network metadata via public RDAP."""
    print("[*] Resolving host IPs and querying ASN / network ranges...")
    host_ip_map = {}
    for h in live_hosts:
        host = h.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        try:
            ip = socket.gethostbyname(host)
            host_ip_map.setdefault(ip, []).append(host)
        except (socket.gaierror, OSError):
            continue

    asn_results = {}
    for ip, hosts in list(host_ip_map.items())[:20]:  # Cap to first 20 IPs to stay fast
        try:
            url = f"https://rdap.arin.net/registry/ip/{ip}"
            req = urllib.request.Request(
                url, headers={"User-Agent": "reconflow-audit", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                handle = data.get("handle", "Unknown")
                name = data.get("name", "Unknown")
                asn_results[ip] = {
                    "network_name": name,
                    "handle": handle,
                    "hosts": hosts,
                }
        except Exception:
            asn_results[ip] = {
                "network_name": "Standard Network",
                "handle": "N/A",
                "hosts": hosts,
            }

    out_file = output_dir / "asn_ranges.json"
    out_file.write_text(json.dumps(asn_results, indent=2), encoding="utf-8")
    print(f"[+] Mapped {len(asn_results)} network ranges across live hosts")
    return asn_results


def audit_http_headers(live_hosts, output_dir: Path, timeout: int = 5) -> list:
    """Inspect HTTP response headers for CORS policies and missing security headers."""
    print("[*] Auditing HTTP response headers & CORS configurations...")
    audit_findings = []

    for host in live_hosts[:30]:  # Audit up to 30 live hosts
        target_url = host if host.startswith("http") else f"https://{host}"
        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "reconflow-audit", "Origin": "https://example.com"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}

                cors_origin = headers.get("access-control-allow-origin")
                cors_creds = headers.get("access-control-allow-credentials")

                missing_sec_headers = []
                for sec_h in ["strict-transport-security", "content-security-policy"]:
                    if sec_h not in headers:
                        missing_sec_headers.append(sec_h)

                audit_findings.append({
                    "url": target_url,
                    "cors_origin": cors_origin or "none",
                    "cors_credentials": cors_creds or "false",
                    "missing_security_headers": missing_sec_headers,
                })
        except Exception:
            continue

    out_file = output_dir / "headers_audit.json"
    out_file.write_text(json.dumps(audit_findings, indent=2), encoding="utf-8")
    print(f"[+] Audited HTTP headers across {len(audit_findings)} endpoints")
    return audit_findings


def audit_cname_records(subdomains, output_dir: Path) -> list:
    """Check DNS CNAME records for subdomains pointing to external cloud services."""
    print("[*] Auditing DNS CNAME records for third-party cloud services...")
    flagged = []

    for sub in subdomains:
        try:
            canonical = socket.getfqdn(sub)
            if canonical and canonical != sub:
                for provider in KNOWN_SERVICE_PROVIDERS:
                    if provider in canonical.lower():
                        # Verify if the canonical name currently resolves to an IP
                        resolves = True
                        try:
                            socket.gethostbyname(canonical)
                        except (socket.gaierror, OSError):
                            resolves = False

                        flagged.append({
                            "subdomain": sub,
                            "cname": canonical,
                            "provider": provider.strip("."),
                            "active_dns": resolves,
                        })
                        break
        except Exception:
            continue

    out_file = output_dir / "cname_audit.json"
    out_file.write_text(json.dumps(flagged, indent=2), encoding="utf-8")
    print(f"[+] Flagged {len(flagged)} external service CNAME record(s)")
    return flagged
