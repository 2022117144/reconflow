"""
reconflow.audits
-----------------
Defensive asset auditing modules:
1. Cloud Asset Identification (AWS S3, GCP Storage, Azure Blob)
2. Network ASN & IP range mapping via RDAP
3. HTTP Header & CORS policy audit
4. DNS CNAME validation for dangling provider records
5. Certificate Transparency (CT) log harvesting (crt.sh)
6. Exposed sensitive configuration and dev files audit
7. WAF & reverse proxy fingerprinting
8. Route harvesting from /robots.txt and /sitemap.xml
9. Email security & DNS governance (SPF and DMARC)
10. Differential recon change detection (subdomains, hosts, ports)
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


def fetch_ct_subdomains(domain: str, output_dir: Path, timeout: int = 10) -> list:
    """Fetch subdomains from public Certificate Transparency logs (crt.sh)."""
    print(f"[*] Querying Certificate Transparency logs for {domain}...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    discovered = set()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "reconflow-audit", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lower()
                    if sub.startswith("*."):
                        sub = sub[2:]
                    if sub and (sub == domain or sub.endswith(f".{domain}")):
                        discovered.add(sub)
    except Exception as e:
        print(f"[!] Warning: crt.sh query failed or timed out: {e}")

    result = sorted(discovered)
    out_file = output_dir / "ct_subdomains.txt"
    out_file.write_text("\n".join(result), encoding="utf-8")
    print(f"[+] Found {len(result)} subdomains in Certificate Transparency logs")
    return result


SENSITIVE_PATHS = [
    ("/.git/HEAD", "Exposed Git repository", ["ref: refs/"]),
    ("/.env", "Environment config file", ["DB_", "APP_", "AWS_", "SECRET", "KEY="]),
    ("/.well-known/security.txt", "Security policy disclosure", ["Contact:"]),
    ("/swagger.json", "Swagger API Specification", ["swagger", "openapi", "paths"]),
    ("/openapi.json", "OpenAPI Specification", ["openapi", "paths", "info"]),
    ("/actuator/health", "Spring Boot Actuator Health", ["UP", "DOWN", "status"]),
    ("/actuator/env", "Spring Boot Actuator Environment", ["propertySources", "activeProfiles"]),
    ("/docker-compose.yml", "Docker Compose configuration", ["version:", "services:"]),
    ("/phpinfo.php", "PHP Info configuration dump", ["PHP Version"]),
    ("/robots.txt", "Robots policy disclosure", ["User-agent"]),
]


def audit_sensitive_files(live_hosts, output_dir: Path, timeout: int = 5) -> list:
    """Audit live hosts for commonly exposed configuration and sensitive dev files."""
    print("[*] Auditing live hosts for exposed sensitive files and dev artifacts...")
    findings = []

    for host in live_hosts[:25]:
        base_url = host.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        for path, description, patterns in SENSITIVE_PATHS:
            target = f"{base_url}{path}"
            try:
                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": "reconflow-audit"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        body = resp.read(4096).decode("utf-8", errors="ignore")
                        if any(p in body for p in patterns):
                            findings.append({
                                "url": target,
                                "file": path,
                                "description": description,
                                "status": resp.status,
                            })
            except Exception:
                continue

    out_file = output_dir / "sensitive_files.json"
    out_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[+] Flagged {len(findings)} exposed sensitive file(s)")
    return findings


WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["cloudfront"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id"],
        "server": ["akamaighost"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-debug-digest"],
        "server": ["fastly"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
    },
}


def detect_waf(live_hosts, output_dir: Path, timeout: int = 5) -> list:
    """Inspect HTTP response headers to fingerprint WAF / CDN reverse proxies."""
    print("[*] Fingerprinting Web Application Firewalls (WAF) & reverse proxies...")
    results = []

    for host in live_hosts[:30]:
        target_url = host if host.startswith("http") else f"https://{host}"
        detected_waf = None
        server_banner = "Unknown"
        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "reconflow-audit"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                server_banner = headers.get("server", "Unknown")

                for waf_name, rules in WAF_SIGNATURES.items():
                    for h in rules["headers"]:
                        if h in headers:
                            detected_waf = waf_name
                            break
                    if detected_waf:
                        break
                    for s in rules["server"]:
                        if s in server_banner.lower():
                            detected_waf = waf_name
                            break
                    if detected_waf:
                        break
        except Exception:
            continue

        results.append({
            "url": target_url,
            "waf": detected_waf or "Direct / No WAF Detected",
            "server": server_banner,
            "protected": detected_waf is not None,
        })

    out_file = output_dir / "waf_detection.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    protected_count = sum(1 for r in results if r["protected"])
    print(f"[+] Fingerprinted {len(results)} hosts: {protected_count} behind CDN/WAF")
    return results


def harvest_sitemaps(live_hosts, output_dir: Path, timeout: int = 5) -> dict:
    """Extract paths from /robots.txt and /sitemap.xml across live hosts."""
    print("[*] Harvesting routes from /robots.txt and /sitemap.xml...")
    discovered_routes = set()
    sitemap_details = {}

    for host in live_hosts[:15]:
        base_url = host.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        routes_for_host = []

        try:
            req = urllib.request.Request(
                f"{base_url}/robots.txt",
                headers={"User-Agent": "reconflow-audit"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    text = resp.read(8192).decode("utf-8", errors="ignore")
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                val = parts[1].strip()
                                if val and val != "/":
                                    routes_for_host.append(val)
                                    discovered_routes.add(val)
        except Exception:
            pass

        try:
            req = urllib.request.Request(
                f"{base_url}/sitemap.xml",
                headers={"User-Agent": "reconflow-audit"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    xml_data = resp.read(16384).decode("utf-8", errors="ignore")
                    matches = re.findall(r"<loc>(https?://[^<]+)</loc>", xml_data, re.IGNORECASE)
                    for m in matches[:50]:
                        routes_for_host.append(m)
                        discovered_routes.add(m)
        except Exception:
            pass

        if routes_for_host:
            sitemap_details[base_url] = sorted(set(routes_for_host))

    out_file = output_dir / "sitemap_routes.json"
    out_file.write_text(json.dumps(sitemap_details, indent=2), encoding="utf-8")

    txt_file = output_dir / "discovered_routes.txt"
    txt_file.write_text("\n".join(sorted(discovered_routes)), encoding="utf-8")

    print(f"[+] Harvested {len(discovered_routes)} unique route(s) across "
          f"{len(sitemap_details)} hosts")
    return sitemap_details


def _query_doh(name: str, rtype: str, timeout: int = 5) -> list:
    """Query DNS over HTTPS (DoH) via Cloudflare or Google DNS."""
    endpoints = [
        f"https://cloudflare-dns.com/dns-query?name={name}&type={rtype}",
        f"https://dns.google/resolve?name={name}&type={rtype}",
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json", "User-Agent": "reconflow-audit"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                answers = data.get("Answer", [])
                return [a.get("data", "").strip('"') for a in answers]
        except Exception:
            continue
    return []


def audit_email_security(domain: str, output_dir: Path, timeout: int = 5) -> dict:
    """Audit domain email spoofing protections (SPF and DMARC policies via DoH)."""
    print(f"[*] Auditing email security & DNS policies for {domain}...")
    result = {
        "domain": domain,
        "spf": {"record": None, "status": "Missing", "spoofable": True},
        "dmarc": {"record": None, "policy": "Missing", "spoofable": True},
        "mx_present": False,
    }

    mx_records = _query_doh(domain, "MX", timeout=timeout)
    if mx_records:
        result["mx_present"] = True

    txt_records = _query_doh(domain, "TXT", timeout=timeout)
    for r in txt_records:
        if r.startswith("v=spf1"):
            result["spf"]["record"] = r
            if "-all" in r:
                result["spf"]["status"] = "HardFail (Strict)"
                result["spf"]["spoofable"] = False
            elif "~all" in r:
                result["spf"]["status"] = "SoftFail (Permissive)"
                result["spf"]["spoofable"] = False
            elif "+all" in r or "?all" in r:
                result["spf"]["status"] = "Permissive (+all / ?all)"
                result["spf"]["spoofable"] = True
            else:
                result["spf"]["status"] = "Configured"
                result["spf"]["spoofable"] = False
            break

    dmarc_records = _query_doh(f"_dmarc.{domain}", "TXT", timeout=timeout)
    for r in dmarc_records:
        if "v=DMARC1" in r:
            result["dmarc"]["record"] = r
            if "p=reject" in r:
                result["dmarc"]["policy"] = "Reject (Enforced)"
                result["dmarc"]["spoofable"] = False
            elif "p=quarantine" in r:
                result["dmarc"]["policy"] = "Quarantine (Enforced)"
                result["dmarc"]["spoofable"] = False
            elif "p=none" in r:
                result["dmarc"]["policy"] = "None (Monitoring Only - Spoofable)"
                result["dmarc"]["spoofable"] = True
            else:
                result["dmarc"]["policy"] = "Configured"
                result["dmarc"]["spoofable"] = False
            break

    out_file = output_dir / "email_security.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    spf_status = result["spf"]["status"]
    dmarc_policy = result["dmarc"]["policy"]
    print(f"[+] Email Security: SPF={spf_status}, DMARC={dmarc_policy}")
    return result


def compute_differential(
    output_dir: Path,
    domain: str,
    current_subs: list,
    current_live: list,
    current_ports: dict,
) -> dict:
    """Compare current scan results against previous snapshot to identify changed assets."""
    print("[*] Computing differential recon changes against previous baseline...")
    snapshot_file = output_dir / "previous_run.json"
    prev_data = {}
    if snapshot_file.exists():
        try:
            prev_data = json.loads(snapshot_file.read_text(encoding="utf-8"))
        except Exception:
            prev_data = {}

    prev_subs = set(prev_data.get("subdomains", []))
    prev_live = set(prev_data.get("live_hosts", []))
    prev_ports = prev_data.get("ports", {})

    new_subs = sorted(list(set(current_subs) - prev_subs)) if prev_subs else []
    removed_subs = sorted(list(prev_subs - set(current_subs))) if prev_subs else []
    new_live = sorted(list(set(current_live) - prev_live)) if prev_live else []
    removed_live = sorted(list(prev_live - set(current_live))) if prev_live else []

    new_ports = {}
    for host, ports in current_ports.items():
        prev_h_ports = set(prev_ports.get(host, []))
        diff_p = sorted(list(set(ports) - prev_h_ports))
        if diff_p:
            new_ports[host] = diff_p

    diff_result = {
        "domain": domain,
        "has_baseline": bool(prev_subs or prev_live),
        "new_subdomains": new_subs,
        "removed_subdomains": removed_subs,
        "new_live_hosts": new_live,
        "removed_live_hosts": removed_live,
        "new_ports": new_ports,
    }

    out_file = output_dir / "diff.json"
    out_file.write_text(json.dumps(diff_result, indent=2), encoding="utf-8")

    current_snapshot = {
        "subdomains": current_subs,
        "live_hosts": current_live,
        "ports": current_ports,
    }
    snapshot_file.write_text(json.dumps(current_snapshot, indent=2), encoding="utf-8")

    if diff_result["has_baseline"]:
        print(f"[+] Diff: +{len(new_subs)} new subdomains, +{len(new_live)} new live hosts, "
              f"+{len(new_ports)} hosts with new ports")
    else:
        print("[+] Diff: Saved baseline snapshot for future change tracking")

    return diff_result
