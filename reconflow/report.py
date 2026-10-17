"""
reconflow.report
-----------------
Builds a single HTML report summarizing every stage of a run, with
severity-colored vuln findings so the signal doesn't get lost in a
wall of text. Falls back gracefully if a given stage was skipped.
"""

from pathlib import Path

SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>reconflow report — {domain}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 960px;
         margin: 40px auto; padding: 0 16px; color: #1f2937; }}
  h1 {{ border-bottom: 2px solid #111827; padding-bottom: 8px; }}
  h2 {{ margin-top: 36px; }}
  .stat {{ display: inline-block; background: #f3f4f6; border-radius: 8px;
           padding: 10px 16px; margin: 4px 8px 4px 0; }}
  .stat b {{ display: block; font-size: 22px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
  th, td {{
    text-align: left; padding: 6px 10px; border-bottom: 1px solid #e5e7eb; font-size: 14px;
  }}
  .badge {{
    color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; text-transform: uppercase;
  }}
  code {{ background: #f3f4f6; padding: 1px 5px; border-radius: 4px; }}
</style>
</head>
<body>
<h1>reconflow report — {domain}</h1>
<p>{summary_stats}</p>
{sections}
</body>
</html>
"""


def _stat(label, value):
    return f'<div class="stat"><b>{value}</b>{label}</div>'


def _vuln_table(findings):
    if not findings:
        return "<p>No vulnerabilities flagged (or nuclei stage skipped).</p>"
    rows = []
    for f in findings:
        info = f.get("info", {})
        sev = info.get("severity", "info")
        color = SEVERITY_COLOR.get(sev, "#6b7280")
        rows.append(
            f"<tr><td><span class='badge' style='background:{color}'>{sev}</span></td>"
            f"<td>{info.get('name', f.get('template-id', '?'))}</td>"
            f"<td><code>{f.get('matched-at', f.get('host', ''))}</code></td></tr>"
        )
    return ("<table><tr><th>Severity</th><th>Finding</th><th>Target</th></tr>"
            + "".join(rows) + "</table>")


def _secrets_table(findings):
    if not findings:
        return "<p>No potential secrets found (or stage skipped).</p>"
    rows = [f"<tr><td>{f['type']}</td><td><code>{f['url']}</code></td>"
            f"<td><code>{f['match']}</code></td></tr>" for f in findings]
    return ("<table><tr><th>Type</th><th>Source</th><th>Match (truncated)</th></tr>"
            + "".join(rows) + "</table>")


def _ports_table(ports_by_host):
    if not ports_by_host:
        return "<p>No port scan data (or stage skipped).</p>"
    rows = [f"<tr><td>{host}</td><td>{', '.join(str(p) for p in sorted(ports))}</td></tr>"
            for host, ports in sorted(ports_by_host.items())]
    return "<table><tr><th>Host</th><th>Open ports</th></tr>" + "".join(rows) + "</table>"


def _endpoints_table(findings):
    if not findings:
        return "<p>No endpoints discovered (or fuzzing stage skipped).</p>"
    rows = [
        f"<tr><td><code>{f.get('status')}</code></td>"
        f"<td><code>{f.get('url')}</code></td>"
        f"<td>{f.get('length')} bytes</td></tr>"
        for f in findings
    ]
    return "<table><tr><th>Status</th><th>URL</th><th>Length</th></tr>" + "".join(rows) + "</table>"


def _cloud_assets_table(findings):
    if not findings:
        return "<p>No external cloud storage references identified.</p>"
    rows = [
        f"<tr><td><code>{f.get('provider')}</code></td>"
        f"<td><code>{f.get('asset')}</code></td></tr>"
        for f in findings
    ]
    return "<table><tr><th>Provider</th><th>Asset Endpoint</th></tr>" + "".join(rows) + "</table>"


def _cname_table(findings):
    if not findings:
        return "<p>No external service CNAME records flagged.</p>"
    rows = [
        f"<tr><td><code>{f.get('subdomain')}</code></td>"
        f"<td><code>{f.get('cname')}</code></td>"
        f"<td>{f.get('provider')}</td>"
        f"<td>{'Active' if f.get('active_dns') else 'Unresolved (Check Record)'}</td></tr>"
        for f in findings
    ]
    return ("<table><tr><th>Subdomain</th><th>CNAME Target</th><th>Service</th>"
            "<th>DNS Status</th></tr>" + "".join(rows) + "</table>")


def _diff_section(diff_data):
    if not diff_data or not diff_data.get("has_baseline"):
        return ""
    new_subs = diff_data.get("new_subdomains", [])
    new_live = diff_data.get("new_live_hosts", [])
    new_ports = diff_data.get("new_ports", {})

    if not (new_subs or new_live or new_ports):
        return (
            "<div style='background:#1f2937;padding:12px;border-radius:6px;margin-bottom:16px;'>"
            "<strong style='color:#10b981;'>Differential Recon:</strong> "
            "No new assets or open ports detected since previous scan.</div>"
        )

    items = []
    if new_subs:
        preview = ", ".join(new_subs[:8]) + (" ..." if len(new_subs) > 8 else "")
        items.append(
            f"<li><strong style='color:#3b82f6;'>+{len(new_subs)} New Subdomain(s):</strong> "
            f"{preview}</li>"
        )
    if new_live:
        preview = ", ".join(new_live[:8]) + (" ..." if len(new_live) > 8 else "")
        items.append(
            f"<li><strong style='color:#10b981;'>+{len(new_live)} New Live Host(s):</strong> "
            f"{preview}</li>"
        )
    if new_ports:
        port_strs = [f"{h}: {p}" for h, p in list(new_ports.items())[:5]]
        items.append(
            f"<li><strong style='color:#f59e0b;'>+{len(new_ports)} Host(s) with "
            f"New Ports:</strong> {'; '.join(port_strs)}</li>"
        )

    return (
        "<div style='background:#1e1e2e;padding:16px;border-radius:6px;border-left:4px "
        "solid #3b82f6;margin-bottom:20px;'><h2>Differential Recon Alerts</h2>"
        f"<ul style='margin:0;padding-left:20px;'>{''.join(items)}</ul></div>"
    )


def _sensitive_files_table(findings):
    if not findings:
        return "<p>No exposed sensitive files or dev artifacts flagged.</p>"
    rows = [
        f"<tr><td><code>{f.get('file')}</code></td>"
        f"<td>{f.get('description')}</td>"
        f"<td><a href='{f.get('url')}' target='_blank'><code>{f.get('url')}</code></a></td></tr>"
        for f in findings
    ]
    return (
        "<table><tr><th>Path</th><th>Artifact Type</th><th>URL</th></tr>"
        + "".join(rows) + "</table>"
    )


def _waf_table(findings):
    if not findings:
        return "<p>No WAF or reverse proxy data available.</p>"
    rows = [
        f"<tr><td><code>{f.get('url')}</code></td>"
        f"<td><strong>{f.get('waf')}</strong></td>"
        f"<td><code>{f.get('server')}</code></td></tr>"
        for f in findings
    ]
    return (
        "<table><tr><th>Endpoint</th><th>WAF / CDN</th><th>Server Banner</th></tr>"
        + "".join(rows) + "</table>"
    )


def _email_security_card(data):
    if not data:
        return "<p>No email security audit performed.</p>"
    spf = data.get("spf", {})
    dmarc = data.get("dmarc", {})
    spf_color = "#ef4444" if spf.get("spoofable") else "#10b981"
    dmarc_color = "#ef4444" if dmarc.get("spoofable") else "#10b981"

    spf_rec = spf.get("record") or "None"
    dmarc_rec = dmarc.get("record") or "None"

    return (
        "<table><tr><th>Policy</th><th>Status</th><th>Record</th></tr>"
        f"<tr><td>SPF</td><td style='color:{spf_color};font-weight:bold;'>"
        f"{spf.get('status')}</td><td><code>{spf_rec}</code></td></tr>"
        f"<tr><td>DMARC</td><td style='color:{dmarc_color};font-weight:bold;'>"
        f"{dmarc.get('policy')}</td><td><code>{dmarc_rec}</code></td></tr></table>"
    )


def _ssl_table(findings):
    if not findings:
        return "<p>No SSL/TLS certificate audit data available.</p>"
    rows = []
    for f in findings:
        status_color = "#ef4444" if (f.get("self_signed") or f.get("expiring_soon")) else "#10b981"
        status_text = "Self-Signed" if f.get("self_signed") else (
            f"Expiring in {f.get('days_remaining')}d" if f.get("expiring_soon") else "Valid"
        )
        days_str = (
            f"{f.get('days_remaining')} days" if f.get("days_remaining") is not None else "N/A"
        )
        rows.append(
            f"<tr><td><code>{f.get('host')}:{f.get('port')}</code></td>"
            f"<td>{f.get('issuer')}</td>"
            f"<td>{days_str}</td>"
            f"<td style='color:{status_color};font-weight:bold;'>{status_text}</td>"
            f"<td><code>{f.get('tls_version')}</code></td></tr>"
        )
    return (
        "<table><tr><th>Host</th><th>Issuer</th><th>Expiry</th>"
        "<th>Cert Status</th><th>TLS Version</th></tr>" + "".join(rows) + "</table>"
    )


def _favicon_table(findings):
    if not findings:
        return "<p>No favicon technology fingerprints matched.</p>"
    rows = [
        f"<tr><td><code>{f.get('url')}</code></td>"
        f"<td><strong>{f.get('technology')}</strong></td>"
        f"<td><code>{f.get('md5')}</code></td></tr>"
        for f in findings if f.get("matched")
    ]
    if not rows:
        return "<p>Favicons collected, but no known framework default hashes matched.</p>"
    return (
        "<table><tr><th>Host</th><th>Identified Technology</th><th>Favicon MD5</th></tr>"
        + "".join(rows) + "</table>"
    )


def _security_grades_table(findings):
    if not findings:
        return "<p>No HTTP security header grading performed.</p>"
    grade_colors = {
        "A+": "#10b981", "A": "#10b981", "B": "#3b82f6",
        "C": "#f59e0b", "D": "#f97316", "F": "#ef4444",
    }
    rows = []
    for f in findings:
        color = grade_colors.get(f.get("grade"), "#9ca3af")
        missing_names = ", ".join(m["name"] for m in f.get("missing_headers", [])) or "None"
        rows.append(
            f"<tr><td><code>{f.get('url')}</code></td>"
            f"<td style='color:{color};font-weight:bold;font-size:16px;'>{f.get('grade')} "
            f"({f.get('score')}/100)</td>"
            f"<td><span style='color:#ef4444;'>{missing_names}</span></td></tr>"
        )
    return (
        "<table><tr><th>Endpoint</th><th>Defensive Grade</th>"
        "<th>Missing Defense Headers</th></tr>" + "".join(rows) + "</table>"
    )


def _security_txt_card(data):
    if not data or not data.get("found"):
        return "<p>No RFC 9116 security.txt policy found.</p>"
    contacts = ", ".join(data.get("contact", [])) or "None"
    return (
        "<table><tr><th>Field</th><th>Value</th></tr>"
        f"<tr><td>Policy URL</td><td><a href='{data.get('url')}' target='_blank'>"
        f"<code>{data.get('url')}</code></a></td></tr>"
        f"<tr><td>Contact(s)</td><td>{contacts}</td></tr>"
        f"<tr><td>Expires</td><td><code>{data.get('expires') or 'N/A'}</code></td></tr>"
        f"<tr><td>Policy</td><td>{data.get('policy') or 'N/A'}</td></tr></table>"
    )


def _zone_transfer_card(findings):
    if not findings:
        return "<p>No DNS zone transfer audit performed.</p>"
    rows = []
    for f in findings:
        vuln = f.get("vulnerable")
        color = "#ef4444" if vuln else "#10b981"
        status_text = "VULNERABLE (AXFR Open)" if vuln else f.get("status", "Secure")
        rows.append(
            f"<tr><td><code>{f.get('nameserver')}</code></td>"
            f"<td><code>{f.get('ip') or 'N/A'}</code></td>"
            f"<td style='color:{color};font-weight:bold;'>{status_text}</td>"
            f"<td>{f.get('records_count', 0)}</td></tr>"
        )
    return (
        "<table><tr><th>Nameserver</th><th>IP</th><th>Status</th>"
        "<th>Records Leaked</th></tr>" + "".join(rows) + "</table>"
    )


def _jwt_table(findings):
    if not findings:
        return "<p>No JWT security flaws detected.</p>"
    risk_colors = {
        "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b",
        "LOW": "#3b82f6", "CLEAN": "#10b981", "INFO": "#6b7280"
    }
    rows = []
    for f in findings:
        color = risk_colors.get(f.get("risk_level"), "#9ca3af")
        vuln_desc = "; ".join(v.get("title") for v in f.get("vulnerabilities", [])) or "None"
        rows.append(
            f"<tr><td><code>{f.get('token_preview')}</code></td>"
            f"<td><code>{f.get('algorithm') or 'None'}</code></td>"
            f"<td style='color:{color};font-weight:bold;'>{f.get('risk_level')}</td>"
            f"<td>{vuln_desc}</td></tr>"
        )
    return (
        "<table><tr><th>Token Preview</th><th>Algorithm</th><th>Risk Level</th>"
        "<th>Vulnerabilities Detected</th></tr>" + "".join(rows) + "</table>"
    )


def _js_endpoints_section(js_data):
    if not js_data or not js_data.get("all_routes"):
        return "<p>No JavaScript API endpoints extracted (or stage skipped).</p>"
    cats = js_data.get("categorized_routes", {})
    badges = []
    if cats.get("admin_internal"):
        cnt = len(cats['admin_internal'])
        badges.append(
            f"<span class='badge' style='background:#ef4444;'>{cnt} Admin/Internal</span>"
        )
    if cats.get("auth_oauth"):
        cnt = len(cats['auth_oauth'])
        badges.append(
            f"<span class='badge' style='background:#f97316;'>{cnt} Auth/OAuth</span>"
        )
    if cats.get("graphql"):
        cnt = len(cats['graphql'])
        badges.append(
            f"<span class='badge' style='background:#8b5cf6;'>{cnt} GraphQL</span>"
        )
    if cats.get("api_rest"):
        cnt = len(cats['api_rest'])
        badges.append(
            f"<span class='badge' style='background:#3b82f6;'>{cnt} REST API</span>"
        )

    summary_html = " ".join(badges) or "<span>Endpoints discovered</span>"

    rows = []
    # Show high priority routes first
    prioritized = (
        cats.get("admin_internal", [])
        + cats.get("auth_oauth", [])
        + cats.get("graphql", [])
        + cats.get("api_rest", [])[:20]
    )
    for r in prioritized[:30]:
        rows.append(f"<tr><td><code>{r}</code></td></tr>")

    return (
        f"<p>{summary_html}</p>"
        "<table><tr><th>Sample Extracted Route / Endpoint</th></tr>" + "".join(rows) + "</table>"
    )


def _dns_sec_card(dns_data):
    if not dns_data:
        return "<p>DNS infrastructure audit not performed.</p>"
    dnssec = dns_data.get("dnssec", {})
    caa = dns_data.get("caa", {})
    ns = dns_data.get("nameservers", {})

    status = dnssec.get("status", "UNKNOWN")
    if status == "SIGNED":
        ds_color = "#10b981"
    elif status == "MISCONFIGURED":
        ds_color = "#ef4444"
    else:
        ds_color = "#f59e0b"
    caa_status = caa.get("status", "UNKNOWN")
    caa_color = "#10b981" if caa_status == "PROTECTED" else "#6b7280"

    dangling_warn = ""
    if ns.get("has_dangling_ns"):
        dangling_warn = (
            f"<div style='color:#ef4444;font-weight:bold;margin-top:8px;'>"
            f"⚠️ ALERT: {len(ns.get('dangling_nameservers', []))} "
            f"dangling/unresolvable nameserver(s) detected!</div>"
        )

    ns_list = ", ".join(ns.get("nameservers", []))
    ds_desc = dnssec.get("description", "")
    caa_sum = caa.get("summary", "")
    return (
        '<div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;'
        'padding:14px;">\n'
        f'  <p><b>DNSSEC:</b> <span class="badge" style="background:{ds_color};">'
        f'{status}</span> &mdash; {ds_desc}</p>\n'
        f'  <p><b>CAA Records (RFC 6844):</b> <span class="badge" '
        f'style="background:{caa_color};">{caa_status}</span> &mdash; {caa_sum}</p>\n'
        f'  <p><b>Nameservers:</b> {ns.get("nameservers_count", 0)} delegations ({ns_list})</p>\n'
        f'  {dangling_warn}\n'
        '</div>\n'
    )


def _cache_audit_table(findings):
    if not findings:
        return "<p>No Web Cache or CDN audit findings.</p>"
    rows = []
    for f in findings:
        cdn = f.get("cdn_detected") or "None / Origin"
        cc = f.get("cache_control") or "none"
        issues = []
        for issue in f.get("findings", []):
            sev = issue.get("severity")
            color = "#ef4444" if sev == "CRITICAL" else "#f59e0b"
            issues.append(
                f"<span style='color:{color};font-weight:bold;'>[{sev}]</span> {issue.get('type')}"
            )
        issues_str = "<br>".join(issues) if issues else "<span style='color:#10b981;'>Clean</span>"
        rows.append(
            f"<tr><td><code>{f.get('url')}</code></td>"
            f"<td>{cdn}</td>"
            f"<td><code>{cc[:40]}</code></td>"
            f"<td>{issues_str}</td></tr>"
        )
    return (
        "<table><tr><th>URL</th><th>CDN Detected</th><th>Cache-Control</th>"
        "<th>Security Observations</th></tr>" + "".join(rows) + "</table>"
    )


def _param_matrix_table(matrix_data):
    if not matrix_data or not matrix_data.get("categories"):
        return "<p>No parameters analyzed.</p>"
    cats = matrix_data.get("categories", {})
    rows = []
    for cat_key, cat in cats.items():
        cnt = cat.get("params_count", 0)
        if cnt == 0:
            continue
        sample_params = ", ".join(
            f"<code>{p['name']}</code>" for p in cat.get("matched_params", [])[:10]
        )
        desc = cat.get("description", "")
        rows.append(
            f"<tr><td><b>{cat.get('label')}</b><br>"
            f"<small style='color:#6b7280;'>{desc}</small></td>"
            f"<td><b>{cnt}</b></td>"
            f"<td>{sample_params}</td></tr>"
        )
    return (
        "<table><tr><th>Attack Surface Category</th><th>Matched Params</th>"
        "<th>Sample Parameters</th></tr>" + "".join(rows) + "</table>"
    )


def build_html_report(domain, output_dir: Path, subdomains, live_hosts,
                      ports_by_host=None, vuln_findings=None,
                      secret_findings=None, fuzz_findings=None,
                      url_count=0, param_count=0,
                      cloud_findings=None, cname_findings=None,
                      sensitive_findings=None, waf_findings=None,
                      email_security=None, diff_data=None,
                      route_count=0,
                      ssl_findings=None, favicon_findings=None,
                      security_grades=None, security_txt=None,
                      permutation_count=0, zone_transfer=None,
                      jwt_findings=None, js_endpoints=None,
                      dns_sec=None, cache_audits=None,
                      param_matrix=None):
    ports_by_host = ports_by_host or {}
    vuln_findings = vuln_findings or []
    secret_findings = secret_findings or []
    fuzz_findings = fuzz_findings or []
    cloud_findings = cloud_findings or []
    cname_findings = cname_findings or []
    sensitive_findings = sensitive_findings or []
    waf_findings = waf_findings or []
    ssl_findings = ssl_findings or []
    favicon_findings = favicon_findings or []
    security_grades = security_grades or []
    zone_transfer = zone_transfer or []
    jwt_findings = jwt_findings or []

    stats = "".join([
        _stat("subdomains", len(subdomains)),
        _stat("live hosts", len(live_hosts)),
        _stat("hosts with open ports", len(ports_by_host)),
        _stat("URLs collected", url_count),
        _stat("unique params", param_count),
        _stat("vuln findings", len(vuln_findings)),
        _stat("potential secrets", len(secret_findings)),
        _stat("discovered endpoints", len(fuzz_findings)),
        _stat("cloud assets", len(cloud_findings)),
        _stat("service CNAMEs", len(cname_findings)),
        _stat("sensitive files", len(sensitive_findings)),
        _stat("WAF protected", sum(1 for w in waf_findings if w.get("protected"))),
        _stat("harvested routes", route_count),
        _stat("SSL audited", len(ssl_findings)),
        _stat("favicon tech", sum(1 for f in favicon_findings if f.get("matched"))),
        _stat("permutations", permutation_count),
        _stat("nameservers", len(zone_transfer)),
        _stat("JWTs audited", len(jwt_findings)),
        _stat("JS routes", js_endpoints.get("total_unique_routes", 0) if js_endpoints else 0),
        _stat(
            "high-value params",
            param_matrix.get("total_high_value_flagged", 0) if param_matrix else 0,
        ),
    ])

    sections = f"""
{_diff_section(diff_data)}
<h2>DNS Infrastructure & Security Posture (DNSSEC & CAA)</h2>
{_dns_sec_card(dns_sec)}
<h2>High-Value Parameter Attack Surface Matrix</h2>
{_param_matrix_table(param_matrix)}
<h2>JavaScript API Routes & Endpoints</h2>
{_js_endpoints_section(js_endpoints)}
<h2>Web Cache & CDN Edge Policy Audit</h2>
{_cache_audit_table(cache_audits)}
<h2>Defensive HTTP Security Header Grades</h2>
{_security_grades_table(security_grades)}
<h2>Vulnerabilities (nuclei)</h2>
{_vuln_table(vuln_findings)}
<h2>Open Ports (naabu)</h2>
{_ports_table(ports_by_host)}
<h2>Discovered Endpoints (ffuf)</h2>
{_endpoints_table(fuzz_findings)}
<h2>Leaked Secrets (JS scan)</h2>
{_secrets_table(secret_findings)}
<h2>JSON Web Token (JWT) Security Analysis</h2>
{_jwt_table(jwt_findings)}
<h2>DNS Zone Transfer (AXFR) Posture</h2>
{_zone_transfer_card(zone_transfer)}
<h2>Exposed Sensitive Files & Dev Artifacts</h2>
{_sensitive_files_table(sensitive_findings)}
<h2>SSL / TLS Certificate Audit</h2>
{_ssl_table(ssl_findings)}
<h2>WAF & Reverse Proxy Detection</h2>
{_waf_table(waf_findings)}
<h2>Favicon Framework Fingerprints</h2>
{_favicon_table(favicon_findings)}
<h2>Email Security & DNS Governance</h2>
{_email_security_card(email_security)}
<h2>RFC 9116 Security.txt Disclosure</h2>
{_security_txt_card(security_txt)}
<h2>Cloud Storage References</h2>
{_cloud_assets_table(cloud_findings)}
<h2>Service CNAME Records</h2>
{_cname_table(cname_findings)}
"""

    html = HTML_TEMPLATE.format(domain=domain, summary_stats=stats, sections=sections)
    out_path = output_dir / "report.html"
    out_path.write_text(html, encoding="utf-8")
    print(f"[+] HTML report saved to {out_path}")
    return out_path
