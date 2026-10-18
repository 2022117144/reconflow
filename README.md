# reconflow

Subdomain discovery, live host probing, port scanning, historical URLs, vulnerability scanning, JS secret scanning, and endpoint fuzzing in **one command**.

`reconflow` chains [subfinder](https://github.com/projectdiscovery/subfinder), [httpx](https://github.com/projectdiscovery/httpx), [naabu](https://github.com/projectdiscovery/naabu), [nuclei](https://github.com/projectdiscovery/nuclei), [gau](https://github.com/lc/gau), and [ffuf](https://github.com/ffuf/ffuf) into a single workflow with streaming results, resumable runs, and clean Markdown, JSON, SARIF, and HTML reports.

> **Use responsibly.** Only scan domains you own or that are explicitly in scope for a bug bounty / pentest program you are authorized to test.

## What it does

1. Finds subdomains of a target (`subfinder` + Certificate Transparency `crt.sh`)
2. Probes which ones are alive and records status code, title and technologies (`httpx`)
3. Port scans live hosts with connect or SYN modes (`naabu`, `--port-scan-type`)
4. Collects historical URLs and extracts unique query parameters (`gau`)
5. Scans live hosts for vulnerabilities and misconfigurations (`nuclei`)
6. Scans discovered JS files for leaked API keys, tokens, and secrets
7. Fuzzes common files and sensitive endpoints (`ffuf`)
8. Audits defensive cloud storage references (AWS S3, GCP, Azure Blob)
9. Maps network ASN and IP CIDR ranges via public RDAP
10. Audits HTTP response headers and permissive CORS policies
11. Inspects DNS CNAME records for external cloud service dependencies (`--cname-check`)
12. Confirms subdomain takeovers with HTTP response fingerprint matching (`--takeover`)
13. Filters targets strictly against HackerOne/Bugcrowd or plain-text scope files with boundary protection & CIDR support (`--scope`)
14. Audits live hosts for exposed sensitive files (`.git`, `.env`, API docs, actuator)
15. Fingerprints Web Application Firewalls (Cloudflare, CloudFront, Akamai, Imperva)
16. Harvests routes from `/robots.txt` and `/sitemap.xml`
17. Audits domain email spoofing protections (SPF and DMARC via DoH)
18. Generates and resolves subdomain permutation variants (`--alterations` and `--perm-scale`)
19. Passive OSINT host intelligence via Shodan InternetDB & Censys (`--passive`)
20. Searches public GitHub repositories for leaked credentials & references (`--github-leaks`)
21. Cross-references detected technology versions against NVD CVEs (`--cve-correlate`)
22. Audits SSL/TLS certificate expiry, SAN coverage, and self-signed status (`--ssl-audit`)
23. Fingerprints web frameworks and portals via favicon MD5 hashes (`--favicon`)
24. Discovers and parses RFC 9116 `security.txt` disclosure policies (`--security-txt`)
25. Grades defensive HTTP response header security posture with A+ to F scorecard (`--security-headers`)
26. Audits authoritative nameservers for open DNS Zone Transfers (`--axfr`)
27. Analyzes JWT tokens for forgery risks, weak secrets, and algorithmic bypasses (`--jwt-audit`)
28. Extracts hidden REST endpoints, GraphQL operations, and parameters from JS bundles (`--js-endpoints`)
29. Audits DNSSEC signatures, RFC 6844 CAA policies, and detects dangling nameserver takeovers (`--dns-sec`)
30. Audits CDN edge caching rules for Web Cache Deception & unkeyed header reflection (`--cache-audit`)
31. Classifies discovered parameters into high-value vulnerability matrices (`--param-miner`)
32. Exports findings to OASIS SARIF v2.1.0 for GitHub Code Scanning integration (`--sarif`)
33. Supports multi-target batch scanning with real-time summary matrices (`-dL`)
34. Tracks differential recon changes across runs (`--diff`)
35. Streams progress to disk so interrupted scans can be safely resumed (`--resume`)
36. Generates summary reports (`report.md`, `report.json`, and severity-colored `report.html`)
37. Posts completion alerts to Discord or Slack webhooks (`--notify`)

## Requirements

- Python 3.8+ (no extra Python packages needed for the core flow)
- [`subfinder`](https://github.com/projectdiscovery/subfinder/releases) and [`httpx`](https://github.com/projectdiscovery/httpx/releases) — required
- [`naabu`](https://github.com/projectdiscovery/naabu/releases) — optional, for `--ports` (uses `--port-scan-type connect` by default on Windows/Linux without requiring root or Npcap)
- [`nuclei`](https://github.com/projectdiscovery/nuclei/releases) — optional, for `--vuln`
- [`gau`](https://github.com/lc/gau) — optional, for `--urls` and `--secrets`
- [`ffuf`](https://github.com/ffuf/ffuf/releases) — optional, for `--fuzz`
- [`gowitness`](https://github.com/sensepost/gowitness/releases) — optional, for `--screenshots`

Every stage degrades gracefully: if a tool isn't installed, reconflow prints a warning and skips that stage instead of crashing.

## Quickstart with Docker (Zero Install)

Run the full toolchain with no manual setup:

```bash
docker build -t reconflow .

# Run scan and save results locally
docker run --rm -v $(pwd)/output:/app/output reconflow -d example.com --full
```

## Local Installation

```bash
git clone https://github.com/ErenYeager1836/reconflow.git
cd reconflow
```

### Automated Linux Toolchain Setup

reconflow includes one-command setup scripts that install and configure all required recon tools, Go binaries, and Nuclei templates for your distribution:

#### Universal Installer (Auto-Detects OS)
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

#### Kali Linux / Parrot OS / Debian / Ubuntu Setup
```bash
chmod +x scripts/setup-debian.sh
./scripts/setup-debian.sh
```
reconflow automatically detects Kali, Parrot, Debian, and Ubuntu at runtime and provides native `apt` commands whenever an optional tool is missing.

#### Arch Linux / BlackArch Setup
```bash
chmod +x scripts/setup-archlinux.sh
./scripts/setup-archlinux.sh
```
reconflow detects Arch and BlackArch at runtime and provides native `pacman` installation commands whenever an optional tool is missing.

#### Fedora / RHEL / CentOS / Rocky Linux Setup
```bash
chmod +x scripts/setup-fedora.sh
./scripts/setup-fedora.sh
```
reconflow detects Fedora and Red Hat derivatives at runtime and provides native installation commands whenever an optional tool is missing.

## Usage

```bash
python reconflow_v2.py -d example.com --full -H "X-Bug-Bounty: hackerone-username" --notify https://discord.com/api/webhooks/...
```

| Option | Description |
| --- | --- |
| `-d`, `--domain` | Target domain (required if not using `-dL`) |
| `-dL`, `--targets-file FILE` | Batch scan multiple domains listed in a file (one per line) |
| `-o`, `--output` | Output folder (default: `output`) |
| `-c`, `--config` | Path to custom YAML/JSON config file (default: `reconflow.yaml`) |
| `--resume` | Resume an interrupted scan without rerunning completed stages |
| `-H`, `--header HEADER` | Custom HTTP header for httpx probing (repeatable, e.g. `-H "X-Bug-Bounty: user"`) |
| `--threads` | Number of threads for httpx probing (default: httpx default) |
| `--timeout` | Timeout in seconds for httpx probing (default: httpx default) |
| `--json` | Also write results to `report.json` |
| `--sarif` | Export findings to SARIF v2.1.0 (`results.sarif`) for GitHub Code Scanning |
| `--screenshots` | Capture screenshots of live hosts (requires gowitness) |
| `--ports` | Port scan live hosts with naabu |
| `--top-ports` | Number of top ports to scan (default: 100) |
| `--port-scan-type` | naabu scan mode: `connect` (default, no root/Npcap needed) or `syn` |
| `--urls` | Collect historical URLs + unique query parameters via gau |
| `--vuln` | Run nuclei against live hosts |
| `--severity` | nuclei severity filter, comma-separated (default: `medium,high,critical`) |
| `--templates PATH` | Custom nuclei template file or directory (nuclei's `-t` flag) |
| `--update-templates` | Update nuclei's default template repository before scanning |
| `--secrets` | Scan discovered JS files for leaked API keys / tokens / JWTs |
| `--jwt TOKEN` | Analyze a specific JWT token for AppSec flaws (`alg: none`, weak secrets) |
| `--jwt-file PATH` | Analyze JWT tokens listed in a text file |
| `--jwt-audit` | Extract and analyze all JWT tokens discovered across JS secrets |
| `--fuzz` | Fuzz endpoints and portals on live hosts with ffuf |
| `--wordlist` | Custom wordlist path for ffuf (default: built-in common list) |
| `--audit` | Run all defensive asset audits (cloud, ASN, headers, CNAME, sensitive, WAF, email, SSL, favicon, security.txt, grades, AXFR, JWT) |
| `--axfr`, `--zone-transfer` | Test authoritative nameservers for open DNS Zone Transfer (AXFR) |
| `--alterations` | Generate and resolve common subdomain permutation & mutation variants (fast DNS check) |
| `--perm-scale` | Scaled subdomain permutation with HTTP confirmation & wildcard filtering |
| `--perm-wordlist PATH` | External wordlist for `--perm-scale` (SecLists-style) |
| `--perm-max COUNT` | Max permutation candidates to probe (default: `5000`) |
| `--passive` | Passive OSINT via Shodan InternetDB (free, keyless, zero packets to target) |
| `--censys-id ID` | Optional Censys API ID for passive host search |
| `--censys-secret SECRET` | Optional Censys API secret for passive host search |
| `--ssl-audit` | Audit SSL/TLS certificate validity, expiry days, and SAN coverage |
| `--favicon` | Fingerprint web application frameworks via favicon MD5 hashes |
| `--security-txt` | Discover and parse RFC 9116 `security.txt` policies across live hosts |
| `--security-headers` | Grade HTTP security header posture with A+ to F scorecard |
| `--cloud-assets` | Detect cloud storage bucket references in discovered URLs and hosts |
| `--asn` | Map network ASN and IP ranges for live hosts via RDAP |
| `--headers` | Audit HTTP security headers and CORS configurations |
| `--cname-check` | Audit DNS CNAME records for external cloud service dependencies |
| `--takeover` | Confirm subdomain takeovers via HTTP fingerprint (requires `--cname-check`) |
| `--scope FILE` | Filter discovered subdomains against HackerOne/Bugcrowd or plain-text scope |
| `--github-leaks` | Search public GitHub code for leaked references and credentials |
| `--github-token TOKEN` | GitHub Personal Access Token for `--github-leaks` |
| `--cve-correlate` | Cross-reference detected tech stack versions against NVD CVEs |
| `--ct-logs` | Harvest subdomains from public Certificate Transparency logs (`crt.sh`) |
| `--sensitive-files` | Audit live hosts for exposed sensitive files (`.git`, `.env`, API docs) |
| `--waf` | Fingerprint Web Application Firewalls (Cloudflare, AWS, Akamai, etc.) |
| `--sitemap` | Harvest routes from `/robots.txt` and `/sitemap.xml` across live hosts |
| `--email-security` | Audit domain SPF and DMARC DNS policies for email spoofing |
| `--js-endpoints` | Extract hidden REST routes, GraphQL operations, and internal query parameters from client JS |
| `--dns-sec` | Audit DNSSEC signature validity, RFC 6844 CAA policies, and detect dangling nameservers (NS takeover) |
| `--cache-audit` | Audit CDN edge caching policies for Web Cache Deception & unkeyed header reflection |
| `--param-miner` | Classify discovered URL query parameters into high-value bug bounty attack surface matrices |
| `--diff` | Highlight new subdomains, live hosts, and newly opened ports vs previous run |
| `--full` | Shortcut for all discovery stages, audits, CT logs, diff, SARIF, AXFR, and HTML report |
| `--html` | Also build a severity-colored HTML report (`report.html`) |
| `--notify URL` | Post a run summary to a Discord/Slack-compatible webhook on finish |

## Configuration (`reconflow.yaml`)

You can set default options and configure API keys for external intelligence sources:

```bash
cp reconflow.yaml.example reconflow.yaml
```

Example `reconflow.yaml`:

```yaml
defaults:
  threads: 50
  timeout: 10
  top_ports: 100
  severity: "medium,high,critical"

subfinder_keys:
  virustotal: "YOUR_VT_API_KEY"
  securitytrails: "YOUR_ST_API_KEY"
  shodan: "YOUR_SHODAN_API_KEY"

notify:
  webhook_url: "https://discord.com/api/webhooks/..."
```

## Example output

```
[*] Loaded configuration from reconflow.yaml
[*] Finding subdomains for example.com...
[+] Found 8 subdomains
[*] Probing for live hosts...
[+] 8 hosts are alive
[*] Port scanning 8 hosts (top 100 ports, mode: connect)...
[+] Open ports found on 3 hosts
[*] Collecting historical URLs for example.com...
[+] Collected 142 URLs, 18 unique parameters
[*] Running nuclei (severity: medium,high,critical) against 8 hosts...
[+] nuclei flagged 2 findings
[*] Scanning 12 JS files for leaked secrets...
[+] Found 1 potential secret(s) — review secrets.json
[*] Fuzzing endpoints across 8 live hosts with ffuf...
[+] ffuf discovered 5 endpoints
[+] HTML report saved to output\example.com\report.html
[+] Report saved to output\example.com\report.md
```

Files created in `output/<domain>/`:

```
state.json              run progress and metadata (enables --resume)
previous_run.json       snapshot baseline for differential change detection
subdomains.txt          all discovered subdomains (subfinder + CT logs)
scope_filtered_out.txt  subdomains excluded by scope filtering (when using --scope)
permutations.txt        resolved subdomain permutation mutations (when using --alterations or --full)
permutations_scaled.json confirmed scaled permutation findings (when using --perm-scale)
ct_subdomains.txt       subdomains discovered from Certificate Transparency logs
live.txt                live hosts with status code, title, tech
urls.txt                collected historical URLs (when using --urls or --full)
params.txt              unique query parameters (when using --urls or --full)
param_matrix.json       categorized bug bounty attack surface parameters (when using --param-miner or --full)
ports.json              open port mappings (when using --ports or --full)
vulns.json              nuclei vulnerability findings (when using --vuln or --full)
secrets.json            extracted secret matches (when using --secrets or --full)
fuzz.json               discovered endpoint paths (when using --fuzz or --full)
cloud_assets.json       discovered cloud storage bucket endpoints (when using --audit)
asn_ranges.json         network ASN & IP ranges mapped via RDAP (when using --audit)
headers_audit.json      HTTP security headers & CORS audit (when using --audit)
cname_audit.json        external service CNAME records (when using --cname-check or --audit)
takeover_confirmed.json confirmed subdomain takeovers via HTTP fingerprints (when using --takeover or --full)
sensitive_files.json    exposed sensitive files & dev artifacts (when using --sensitive-files or --audit)
waf_detection.json      WAF/CDN reverse proxy fingerprinting (when using --waf or --audit)
sitemap_routes.json     extracted routes from robots.txt and sitemaps (when using --sitemap or --audit)
discovered_routes.txt   plain list of all harvested unique paths
email_security.json     SPF and DMARC spoofing policy audit (when using --email-security or --audit)
zone_transfer.json      DNS Zone Transfer AXFR test results (when using --axfr, --audit, or --full)
jwt_analysis.json       decoded JWT vulnerability & secret analysis (when using --jwt* or --full)
ssl_audit.json          SSL/TLS certificate expiration & SAN audit (when using --ssl-audit or --audit)
favicon_fingerprints.json framework detection via favicon MD5 hashes (when using --favicon or --audit)
security_txt.json       RFC 9116 vulnerability disclosure policies (when using --security-txt or --audit)
security_grades.json    defensive HTTP security header letter grades (when using --security-headers or --audit)
js_endpoints.json       hidden REST routes, GraphQL ops, and params from JS (when using --js-endpoints or --full)
dnssec_audit.json       DNSSEC, CAA records, and dangling NS status (when using --dns-sec or --full)
cache_audit.json        CDN edge caching & Web Cache Deception findings (when using --cache-audit or --full)
github_leaks.json       public GitHub leaked credentials & references (when using --github-leaks)
cve_correlations.json   detected tech stack mapped to NVD CVEs (when using --cve-correlate)
diff.json               new & removed subdomains, live hosts, and ports (when using --diff)
results.sarif           OASIS SARIF v2.1.0 code scanning report (when using --sarif or --full)
batch_summary.json      multi-target batch progress and summary metrics (when using -dL)
report.md               summary Markdown report
report.json             structured JSON report (when using --json)
report.html             severity-colored HTML dashboard with diff alerts
screenshots/            captured screenshots of live hosts (when using --screenshots)
```

## Known limitations

- **Wildcard DNS domains** return many fake "live" hosts that all point to the same server. reconflow detects them and filters the fake hosts (use `--keep-wildcard` to disable).

## Roadmap

- [x] Wildcard DNS detection & filtering
- [x] Live progress display & streaming run state (`--resume`)
- [x] `--threads` and `--timeout` tuning
- [x] JSON report output (`--json`)
- [x] Screenshots of live hosts via gowitness (`--screenshots`)
- [x] Port scanning with naabu (`--ports`, `--top-ports`, `--port-scan-type`)
- [x] Historical URL + parameter collection via gau (`--urls`)
- [x] Vulnerability scanning via nuclei (`--vuln`, `--templates`)
- [x] JS secret & credential pattern scanning (`--secrets`)
- [x] Webhook notifications for Discord & Slack (`--notify`)
- [x] Severity-colored HTML dashboard (`--html`)
- [x] Config file for API keys & default flags (`reconflow.yaml`)
- [x] Directory & endpoint fuzzing via ffuf (`--fuzz`, `--wordlist`)
- [x] Docker image for zero-install usage
- [x] Public cloud storage & S3 bucket reference detection (`--cloud-assets`)
- [x] Network ASN and IP range mapping via RDAP (`--asn`)
- [x] HTTP security header and CORS configuration audits (`--headers`)
- [x] DNS CNAME external service provider validation (`--cname-check`)
- [x] Certificate Transparency (CT) log harvesting (`--ct-logs`)
- [x] Exposed sensitive files & dev artifact auditing (`--sensitive-files`)
- [x] Web Application Firewall (WAF) & CDN fingerprinting (`--waf`)
- [x] Robots.txt and sitemap route harvesting (`--sitemap`)
- [x] Email security & DNS governance (SPF / DMARC) (`--email-security`)
- [x] Subdomain permutation & mutation engines (`--alterations`, `--perm-scale`)
- [x] Passive OSINT lookups via Shodan InternetDB & Censys (`--passive`)
- [x] Custom Nuclei templates and auto-update support (`--templates`)
- [x] Confirmed subdomain takeover HTTP fingerprinting (`--takeover`)
- [x] Bug bounty scope filtering with boundary protection & CIDR support (`--scope`)
- [x] Public GitHub secret & credential leak discovery (`--github-leaks`)
- [x] Tech-stack version CVE correlation against NVD (`--cve-correlate`)
- [x] Multi-target batch scanning (`-dL` / `--targets-file`)
- [x] OASIS SARIF v2.1.0 export for GitHub Code Scanning (`--sarif`)
- [x] Authoritative DNS Zone Transfer (AXFR) misconfiguration check (`--axfr`)
- [x] JSON Web Token (JWT) AppSec analysis & secret cracking (`--jwt-audit`)
- [x] SSL/TLS certificate expiration & SAN auditing (`--ssl-audit`)
- [x] Web framework favicon MD5 fingerprinting (`--favicon`)
- [x] RFC 9116 `security.txt` policy harvesting (`--security-txt`)
- [x] Defensive HTTP response header posture grading (`--security-headers`)
- [x] Hidden REST endpoints & GraphQL operation extraction from JS (`--js-endpoints`)
- [x] DNSSEC validation, CAA policies, and dangling nameserver takeover detection (`--dns-sec`)
- [x] CDN edge caching & Web Cache Deception auditing (`--cache-audit`)
- [x] Bug bounty parameter vulnerability classification matrix (`--param-miner`)
- [x] Differential recon & change tracking (`--diff`)
- [x] Custom HTTP request headers for bug bounty identification (`-H` / `--header`)

## Contributing

Contributions are welcome. Look for issues labelled `good first issue`.

## License

MIT
