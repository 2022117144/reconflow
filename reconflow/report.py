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


def build_html_report(domain, output_dir: Path, subdomains, live_hosts,
                      ports_by_host=None, vuln_findings=None,
                      secret_findings=None, fuzz_findings=None,
                      url_count=0, param_count=0,
                      cloud_findings=None, cname_findings=None,
                      sensitive_findings=None, waf_findings=None,
                      email_security=None, diff_data=None,
                      route_count=0):
    ports_by_host = ports_by_host or {}
    vuln_findings = vuln_findings or []
    secret_findings = secret_findings or []
    fuzz_findings = fuzz_findings or []
    cloud_findings = cloud_findings or []
    cname_findings = cname_findings or []
    sensitive_findings = sensitive_findings or []
    waf_findings = waf_findings or []

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
    ])

    sections = f"""
{_diff_section(diff_data)}
<h2>Vulnerabilities (nuclei)</h2>
{_vuln_table(vuln_findings)}
<h2>Open Ports (naabu)</h2>
{_ports_table(ports_by_host)}
<h2>Discovered Endpoints (ffuf)</h2>
{_endpoints_table(fuzz_findings)}
<h2>Leaked Secrets (JS scan)</h2>
{_secrets_table(secret_findings)}
<h2>Exposed Sensitive Files & Dev Artifacts</h2>
{_sensitive_files_table(sensitive_findings)}
<h2>WAF & Reverse Proxy Detection</h2>
{_waf_table(waf_findings)}
<h2>Email Security & DNS Governance</h2>
{_email_security_card(email_security)}
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
