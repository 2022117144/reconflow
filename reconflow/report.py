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


def build_html_report(domain, output_dir: Path, subdomains, live_hosts,
                      ports_by_host=None, vuln_findings=None,
                      secret_findings=None, fuzz_findings=None,
                      url_count=0, param_count=0,
                      cloud_findings=None, cname_findings=None):
    ports_by_host = ports_by_host or {}
    vuln_findings = vuln_findings or []
    secret_findings = secret_findings or []
    fuzz_findings = fuzz_findings or []
    cloud_findings = cloud_findings or []
    cname_findings = cname_findings or []

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
    ])

    sections = f"""
<h2>Vulnerabilities (nuclei)</h2>
{_vuln_table(vuln_findings)}
<h2>Open Ports (naabu)</h2>
{_ports_table(ports_by_host)}
<h2>Discovered Endpoints (ffuf)</h2>
{_endpoints_table(fuzz_findings)}
<h2>Leaked Secrets (JS scan)</h2>
{_secrets_table(secret_findings)}
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
