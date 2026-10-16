# reconflow

Subdomain discovery, live host probing, port scanning, historical URLs, vulnerability scanning, JS secret scanning, and endpoint fuzzing in **one command**.

`reconflow` chains [subfinder](https://github.com/projectdiscovery/subfinder), [httpx](https://github.com/projectdiscovery/httpx), [naabu](https://github.com/projectdiscovery/naabu), [nuclei](https://github.com/projectdiscovery/nuclei), [gau](https://github.com/lc/gau), and [ffuf](https://github.com/ffuf/ffuf) into a single workflow with streaming results, resumable runs, and clean Markdown and HTML reports.

> **Use responsibly.** Only scan domains you own or that are explicitly in scope for a bug bounty / pentest program you are authorized to test.

## What it does

1. Finds subdomains of a target (`subfinder`)
2. Probes which ones are alive and records status code, title and technologies (`httpx`)
3. Port scans live hosts (`naabu`)
4. Collects historical URLs and extracts unique query parameters (`gau`)
5. Scans live hosts for vulnerabilities and misconfigurations (`nuclei`)
6. Scans discovered JS files for leaked API keys, tokens, and secrets
7. Fuzzes common files and sensitive endpoints (`ffuf`)
8. Audits defensive cloud storage references (AWS S3, GCP, Azure Blob)
9. Maps network ASN and IP CIDR ranges via public RDAP
10. Audits HTTP response headers and permissive CORS policies
11. Inspects DNS CNAME records for external cloud service dependencies
12. Streams progress to disk so interrupted scans can be safely resumed (`--resume`)
13. Generates summary reports (`report.md`, `report.json`, and severity-colored `report.html`)
14. Posts completion alerts to Discord or Slack webhooks

## Requirements

- Python 3.8+ (no extra Python packages needed for the core flow)
- [`subfinder`](https://github.com/projectdiscovery/subfinder/releases) and [`httpx`](https://github.com/projectdiscovery/httpx/releases) — required
- [`naabu`](https://github.com/projectdiscovery/naabu/releases) — optional, for `--ports`
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

### Arch Linux / BlackArch Setup

If you are running Arch Linux or BlackArch, use the automated setup script to install the complete toolchain in one command:

```bash
chmod +x scripts/setup-archlinux.sh
./scripts/setup-archlinux.sh
```

reconflow also detects Arch/BlackArch at runtime and provides native `pacman` installation commands whenever an optional tool is missing.

## Usage

```bash
python reconflow_v2.py -d example.com --full --notify https://discord.com/api/webhooks/...
```

| Option | Description |
| --- | --- |
| `-d`, `--domain` | Target domain (required) |
| `-o`, `--output` | Output folder (default: `output`) |
| `-c`, `--config` | Path to custom YAML/JSON config file (default: `reconflow.yaml`) |
| `--resume` | Resume an interrupted scan without rerunning completed stages |
| `--threads` | Number of threads for httpx probing (default: httpx default) |
| `--timeout` | Timeout in seconds for httpx probing (default: httpx default) |
| `--json` | Also write results to `report.json` |
| `--screenshots` | Capture screenshots of live hosts (requires gowitness) |
| `--ports` | Port scan live hosts with naabu |
| `--top-ports` | Number of top ports to scan (default: 100) |
| `--urls` | Collect historical URLs + unique query parameters via gau |
| `--vuln` | Run nuclei against live hosts |
| `--severity` | nuclei severity filter, comma-separated (default: `medium,high,critical`) |
| `--secrets` | Scan discovered JS files for leaked API keys / tokens / JWTs |
| `--fuzz` | Fuzz endpoints and portals on live hosts with ffuf |
| `--wordlist` | Custom wordlist path for ffuf (default: built-in common list) |
| `--audit` | Run all defensive asset audits (cloud, ASN, headers, CNAME) |
| `--cloud-assets` | Detect cloud storage bucket references in discovered URLs and hosts |
| `--asn` | Map network ASN and IP ranges for live hosts via RDAP |
| `--headers` | Audit HTTP security headers and CORS configurations |
| `--cname-check` | Audit DNS CNAME records for external cloud service dependencies |
| `--full` | Shortcut for all discovery stages, audits, and HTML report |
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
[*] Port scanning 8 hosts (top 100 ports)...
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
state.json         run progress and metadata (enables --resume)
subdomains.txt     all discovered subdomains
live.txt           live hosts with status code, title, tech
urls.txt           collected URLs (when using --urls or --full)
params.txt         unique query parameters (when using --urls or --full)
ports.json         open port mappings (when using --ports or --full)
vulns.json         nuclei vulnerability findings (when using --vuln or --full)
secrets.json       extracted secret matches (when using --secrets or --full)
fuzz.json          discovered endpoint paths (when using --fuzz or --full)
cloud_assets.json  discovered cloud storage bucket endpoints (when using --audit)
asn_ranges.json    network ASN & IP ranges mapped via RDAP (when using --audit)
headers_audit.json HTTP security headers & CORS audit (when using --audit)
cname_audit.json   external service CNAME records (when using --audit)
report.md          summary Markdown report
report.json        structured JSON report (when using --json)
report.html        severity-colored HTML dashboard (when using --html or --full)
screenshots/       captured screenshots of live hosts (when using --screenshots)
```

## Known limitations

- **Wildcard DNS domains** return many fake "live" hosts that all point to the same server. reconflow detects them and filters the fake hosts (use `--keep-wildcard` to disable).

## Roadmap

- [x] Wildcard DNS detection
- [x] Live progress display
- [x] `--threads` and `--timeout` options
- [x] JSON report output
- [x] Screenshots of live hosts
- [x] Port scanning (naabu)
- [x] Historical URL + parameter collection (gau)
- [x] Vulnerability scanning (nuclei)
- [x] JS secret scanning
- [x] Webhook notifications
- [x] HTML report
- [x] Save results as they come in (streaming / resumable runs via `--resume`)
- [x] Config file for API keys & default flags (`reconflow.yaml`)
- [x] Directory/endpoint fuzzing (`ffuf` integration)
- [x] Docker image for zero-install usage
- [x] Public cloud storage & S3 bucket reference detection
- [x] Network ASN and IP range mapping via RDAP
- [x] HTTP security header and CORS configuration audits
- [x] DNS CNAME external service provider validation

## Contributing

Contributions are welcome. Look for issues labelled `good first issue`.

## License

MIT
