"""
reconflow.passive_lookup
--------------------------
Genuinely passive recon: no requests are ever sent to the target itself,
only to third-party services that already scanned it. Good complement to
--ports (naabu), which does touch the target directly.

1. Shodan InternetDB — free, no API key, no rate-limit auth needed.
   Returns open ports, CPEs, hostnames, tags and known CVEs for an IP,
   refreshed weekly by Shodan's own scanning.
2. Censys (optional) — needs a free-tier API ID/secret from censys.io.
   Certificate and host search, also passive (queries Censys's index,
   never the target).
"""

import base64
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
CENSYS_HOSTS_URL = "https://search.censys.io/api/v2/hosts/{ip}"


def _resolve_ips(hosts):
    ips = set()
    for h in hosts:
        clean = h.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        try:
            ips.add(socket.gethostbyname(clean))
        except (socket.gaierror, OSError):
            continue
    return sorted(ips)


def shodan_internetdb_lookup(live_hosts, output_dir: Path, timeout: int = 8):
    """No API key required — Shodan's InternetDB is free and keyless."""
    ips = _resolve_ips(live_hosts)
    if not ips:
        print("[*] No resolvable IPs for passive Shodan lookup")
        return []

    print(f"[*] Querying Shodan InternetDB for {len(ips)} IP(s) "
          f"(passive, no packets sent to target)...")
    results = []
    for ip in ips:
        url = INTERNETDB_URL.format(ip=ip)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "reconflow-passive"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("ports") or data.get("vulns"):
                results.append({
                    "ip": ip,
                    "hostnames": data.get("hostnames", []),
                    "ports": data.get("ports", []),
                    "cpes": data.get("cpes", []),
                    "vulns": data.get("vulns", []),
                    "tags": data.get("tags", []),
                })
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # no data for this IP, not an error
        except Exception:
            continue
        time.sleep(0.5)  # be a polite neighbor

    out_file = output_dir / "shodan_passive.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    vuln_count = sum(len(r["vulns"]) for r in results)
    print(f"[+] Shodan passive lookup: {len(results)} host(s) with data, "
          f"{vuln_count} known CVE(s) flagged by Shodan's own scanning")
    return results


def censys_lookup(live_hosts, output_dir: Path, api_id: str, api_secret: str, timeout: int = 10):
    if not api_id or not api_secret:
        print("[!] --censys-id / --censys-secret not provided — skipping Censys lookup. "
              "Get a free-tier key at https://search.censys.io/account/api")
        return []

    ips = _resolve_ips(live_hosts)
    if not ips:
        return []

    print(f"[*] Querying Censys for {len(ips)} IP(s)...")
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    results = []

    for ip in ips:
        url = CENSYS_HOSTS_URL.format(ip=ip)
        try:
            req = urllib.request.Request(
                url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            result = data.get("result", {})
            services = result.get("services", [])
            if services:
                results.append({
                    "ip": ip,
                    "services": [
                        {"port": s.get("port"), "service": s.get("service_name")}
                        for s in services
                    ],
                    "autonomous_system": result.get("autonomous_system", {}).get("name"),
                })
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                print("[!] Censys auth rejected — check --censys-id/--censys-secret.")
                break
            if e.code == 404:
                continue
        except Exception:
            continue
        time.sleep(1)

    out_file = output_dir / "censys_passive.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[+] Censys passive lookup: {len(results)} host(s) with data")
    return results
