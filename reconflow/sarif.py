"""
reconflow.sarif
-----------------
Exports reconflow security findings to SARIF v2.1.0 (Static Analysis Results
Interchange Format). Enables native GitHub Code Scanning integration and alerts
under the repository 'Security' tab.
"""

import json
from pathlib import Path

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

RULES = {
    "RF-TAKEOVER": {
        "name": "SubdomainTakeoverConfirmed",
        "shortDescription": {"text": "Confirmed subdomain takeover via dangling CNAME"},
        "fullDescription": {
            "text": "A DNS CNAME points to an external cloud service that returns an "
                    "unclaimed tenant signature. An attacker can claim this resource to "
                    "serve content on this domain."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "dns", "takeover", "cname"]},
    },
    "RF-AXFR": {
        "name": "DnsZoneTransferOpen",
        "shortDescription": {"text": "DNS Zone Transfer (AXFR) is open on nameserver"},
        "fullDescription": {
            "text": "The authoritative DNS nameserver answered an unrestricted AXFR query, "
                    "leaking internal and external DNS zone topology."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "dns", "axfr", "information-disclosure"]},
    },
    "RF-JWT-VULN": {
        "name": "JsonWebTokenSecurityFlaw",
        "shortDescription": {"text": "Security flaw detected in JSON Web Token"},
        "fullDescription": {
            "text": "A discovered JWT uses an insecure algorithm (e.g. alg:none), is signed "
                    "with a weak/default secret, or lacks expiration controls."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "jwt", "crypto", "authentication"]},
    },
    "RF-VULN-CRITICAL": {
        "name": "NucleiFindingCritical",
        "shortDescription": {"text": "Critical vulnerability flagged by Nuclei"},
        "fullDescription": {"text": "A critical severity finding reported by active scanning."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "vulnerability", "critical"]},
    },
    "RF-VULN-HIGH": {
        "name": "NucleiFindingHigh",
        "shortDescription": {"text": "High severity vulnerability flagged by Nuclei"},
        "fullDescription": {"text": "A high severity finding reported by active scanning."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "vulnerability", "high"]},
    },
    "RF-VULN-MED": {
        "name": "NucleiFindingMedium",
        "shortDescription": {"text": "Medium severity vulnerability flagged by Nuclei"},
        "fullDescription": {"text": "A medium severity finding reported by active scanning."},
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "vulnerability", "medium"]},
    },
    "RF-SECRET": {
        "name": "ExposedSecretOrToken",
        "shortDescription": {"text": "Potential sensitive secret or token found in source"},
        "fullDescription": {
            "text": "Pattern match detected an API key, credential, or token in client-side code."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "secrets", "credential-leak"]},
    },
    "RF-SENSITIVE-FILE": {
        "name": "ExposedSensitiveFile",
        "shortDescription": {"text": "Sensitive file or dev artifact accessible on live host"},
        "fullDescription": {
            "text": "A sensitive configuration file, backup, or environment artifact was exposed."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "configuration", "exposure"]},
    },
    "RF-EMAIL-SPOOF": {
        "name": "EmailSpoofingRisk",
        "shortDescription": {"text": "Permissive or missing SPF/DMARC DNS configuration"},
        "fullDescription": {
            "text": "The domain lacks strict SPF/DMARC enforcement, allowing email spoofing."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "email", "dns"]},
    },
    "RF-CVE-CORRELATE": {
        "name": "KnownTechnologyCve",
        "shortDescription": {"text": "Detected technology correlates with known CVEs"},
        "fullDescription": {
            "text": "A running service version matched published CVE records in the NVD database."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "cve", "known-vulnerabilities"]},
    },
    "RF-DANGLING-NS": {
        "name": "DanglingNameserverDelegation",
        "shortDescription": {"text": "Authoritative nameserver is unresolvable or dangling"},
        "fullDescription": {
            "text": (
                "A nameserver assigned to the domain fails to resolve or belongs to an unassigned "
                "cloud DNS tenant, creating a full domain takeover risk."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "dns", "nameserver", "takeover"]},
    },
    "RF-DNSSEC-MISSING": {
        "name": "DnssecMissingOrUnsigned",
        "shortDescription": {"text": "DNSSEC is not enabled or zone is unsigned"},
        "fullDescription": {
            "text": (
                "The domain lacks DNSSEC records, making DNS responses susceptible to "
                "cache poisoning and spoofing."
            )
        },
        "defaultConfiguration": {"level": "note"},
        "properties": {"tags": ["security", "dns", "dnssec"]},
    },
    "RF-CAA-MISSING": {
        "name": "CaaRecordMissing",
        "shortDescription": {"text": "CAA record missing (unrestricted certificate issuance)"},
        "fullDescription": {
            "text": (
                "The domain lacks RFC 6844 CAA records, allowing any CA in the WebPKI "
                "to issue certificates."
            )
        },
        "defaultConfiguration": {"level": "note"},
        "properties": {"tags": ["security", "dns", "caa", "pki"]},
    },
    "RF-CACHE-SENSITIVE-PUBLIC": {
        "name": "WebCacheDeceptionSensitiveDataPublic",
        "shortDescription": {
            "text": "Sensitive cookies or authentication data allowed in public cache"
        },
        "fullDescription": {
            "text": (
                "The HTTP response includes Set-Cookie or auth data while Cache-Control "
                "allows public caching."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "cache", "web-cache-deception", "cdn"]},
    },
    "RF-UNKEYED-HEADER-REFLECTION": {
        "name": "UnkeyedHeaderReflection",
        "shortDescription": {"text": "Unkeyed header reflected in HTTP response"},
        "fullDescription": {
            "text": (
                "Headers like X-Forwarded-Host are reflected in response headers, "
                "creating potential web cache poisoning vectors."
            )
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "cache", "cache-poisoning", "headers"]},
    },
}


def _make_location(uri: str) -> list[dict]:
    is_http = uri.startswith("http://") or uri.startswith("https://")
    clean_uri = uri if is_http else f"https://{uri}"
    return [{
        "physicalLocation": {
            "artifactLocation": {"uri": clean_uri},
            "region": {"startLine": 1},
        }
    }]


def generate_sarif(domain: str, output_dir: Path, findings_dict: dict) -> dict:
    """
    Transforms reconflow findings into a valid SARIF v2.1.0 document.
    Writes output_dir / 'results.sarif'.
    """
    results = []

    # 1. Takeover findings
    for t in findings_dict.get("takeovers", []):
        sub = t.get("subdomain") or domain
        service = t.get("matched_service", "Unknown Service")
        results.append({
            "ruleId": "RF-TAKEOVER",
            "level": "error",
            "message": {
                "text": f"Subdomain takeover confirmed on {sub} pointing to {service} "
                        f"(CNAME: {t.get('cname')})"
            },
            "locations": _make_location(sub),
        })

    # 2. Zone transfer (AXFR) findings
    for z in findings_dict.get("zone_transfers", []):
        if z.get("vulnerable"):
            ns = z.get("nameserver") or "nameserver"
            results.append({
                "ruleId": "RF-AXFR",
                "level": "error",
                "message": {
                    "text": f"DNS Zone Transfer (AXFR) allowed on {ns} ({z.get('ip')}). "
                            f"{z.get('records_count', 0)} DNS records extracted."
                },
                "locations": _make_location(domain),
            })

    # 3. JWT findings
    for j in findings_dict.get("jwts", []):
        for v in j.get("vulnerabilities", []):
            level = "error" if v.get("severity") in ("CRITICAL", "HIGH") else "warning"
            results.append({
                "ruleId": "RF-JWT-VULN",
                "level": level,
                "message": {
                    "text": f"JWT issue [{v.get('severity')}]: {v.get('title')} — "
                            f"{v.get('description')}"
                },
                "locations": _make_location(domain),
            })

    # 4. Nuclei findings
    for n in findings_dict.get("vulns", []):
        info = n.get("info", {})
        sev = str(info.get("severity", "medium")).lower()
        if sev == "critical":
            rule_id = "RF-VULN-CRITICAL"
            level = "error"
        elif sev == "high":
            rule_id = "RF-VULN-HIGH"
            level = "error"
        else:
            rule_id = "RF-VULN-MED"
            level = "warning"
        matched = n.get("matched-at") or n.get("host") or domain
        name = info.get("name") or n.get("template-id") or "Nuclei Finding"
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"Nuclei [{sev.upper()}]: {name} at {matched}"},
            "locations": _make_location(matched),
        })

    # 5. Secrets findings
    for s in findings_dict.get("secrets", []):
        results.append({
            "ruleId": "RF-SECRET",
            "level": "error",
            "message": {
                "text": f"Potential {s.get('type')} secret exposed in {s.get('url')} "
                        f"(match preview: {s.get('match')})"
            },
            "locations": _make_location(s.get("url") or domain),
        })

    # 6. Sensitive files findings
    for sf in findings_dict.get("sensitive_files", []):
        results.append({
            "ruleId": "RF-SENSITIVE-FILE",
            "level": "warning",
            "message": {
                "text": f"Exposed sensitive file: {sf.get('url')} "
                        f"(HTTP {sf.get('status')}, size: {sf.get('content_length')} bytes)"
            },
            "locations": _make_location(sf.get("url") or domain),
        })

    # 7. Email security findings
    email_sec = findings_dict.get("email_security", {})
    if email_sec:
        spf_spoof = email_sec.get("spf", {}).get("spoofable")
        dmarc_spoof = email_sec.get("dmarc", {}).get("spoofable")
        if spf_spoof or dmarc_spoof:
            results.append({
                "ruleId": "RF-EMAIL-SPOOF",
                "level": "warning",
                "message": {
                    "text": f"Email spoofing vulnerability on {domain}: SPF status="
                            f"{email_sec.get('spf', {}).get('status')}, DMARC policy="
                            f"{email_sec.get('dmarc', {}).get('policy')}"
                },
                "locations": _make_location(domain),
            })

    # 8. CVE correlation findings
    for cve in findings_dict.get("cves", []):
        tech = cve.get("tech") or "Detected Tech"
        for c in cve.get("cves", []):
            results.append({
                "ruleId": "RF-CVE-CORRELATE",
                "level": "warning",
                "message": {
                    "text": f"Known CVE {c.get('cve_id')} for {tech}: {c.get('description')}"
                },
                "locations": _make_location(domain),
            })

    # 9. DNS Security (DNSSEC, CAA, Dangling NS)
    dns_sec = findings_dict.get("dns_sec", {})
    if dns_sec:
        dnssec_data = dns_sec.get("dnssec", {})
        if dnssec_data.get("status") in ["UNSIGNED", "MISCONFIGURED"]:
            results.append({
                "ruleId": "RF-DNSSEC-MISSING",
                "level": "note",
                "message": {
                    "text": (
                        f"DNSSEC status for {domain}: {dnssec_data.get('status')} - "
                        f"{dnssec_data.get('description')}"
                    )
                },
                "locations": _make_location(domain),
            })
        caa_data = dns_sec.get("caa", {})
        if caa_data and not caa_data.get("has_caa"):
            results.append({
                "ruleId": "RF-CAA-MISSING",
                "level": "note",
                "message": {
                    "text": (
                        f"Domain {domain} lacks CAA record: any CA in the WebPKI can issue "
                        "valid certificates"
                    )
                },
                "locations": _make_location(domain),
            })
        ns_data = dns_sec.get("nameservers", {})
        for dns_item in ns_data.get("dangling_nameservers", []):
            ns_err = dns_item.get('error')
            results.append({
                "ruleId": "RF-DANGLING-NS",
                "level": "error",
                "message": {
                    "text": (
                        f"Dangling nameserver delegation on {domain}: "
                        f"{dns_item.get('nameserver')} failed to resolve ({ns_err})"
                    )
                },
                "locations": _make_location(domain),
            })

    # 10. Web Cache & CDN Policy Findings
    for cache_item in findings_dict.get("cache_audits", []):
        target_u = cache_item.get("url") or domain
        for f in cache_item.get("findings", []):
            is_sensitive = f.get("type") == "SENSITIVE_DATA_PUBLIC_CACHE"
            rule_id = (
                "RF-CACHE-SENSITIVE-PUBLIC" if is_sensitive else "RF-UNKEYED-HEADER-REFLECTION"
            )
            lvl = "error" if f.get("severity") == "CRITICAL" else "warning"
            results.append({
                "ruleId": rule_id,
                "level": lvl,
                "message": {
                    "text": f"{f.get('description')} at {target_u}"
                },
                "locations": _make_location(target_u),
            })

    rule_list = [{"id": k, **v} for k, v in RULES.items()]

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "reconflow",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/ErenYeager1836/reconflow",
                        "rules": rule_list,
                    }
                },
                "results": results,
            }
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "results.sarif"
    out_file.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
    print(f"[+] SARIF export: {len(results)} finding(s) written to {out_file}")
    return sarif_doc
