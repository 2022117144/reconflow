# reconflow

Subdomain discovery, live host probing, port scanning, historical URLs, vulnerability scanning, and JS secret scanning in **one command**.

`reconflow` chains [subfinder](https://github.com/projectdiscovery/subfinder), [httpx](https://github.com/projectdiscovery/httpx), [naabu](https://github.com/projectdiscovery/naabu), [nuclei](https://github.com/projectdiscovery/nuclei), and [gau](https://github.com/lc/gau) into a single workflow and writes clean Markdown and HTML reports, so you don't have to run each tool by hand and copy results between them.

> **Use responsibly.** Only scan domains you own or that are explicitly in scope for a bug bounty / pentest program you are authorized to test.

## What it does

1. Finds subdomains of a target (subfinder)
2. Probes which ones are alive and records status code, title and technologies (httpx)
3. Port scans live hosts (naabu)
4. Collects historical URLs and extracts unique query parameters (gau)
5. Scans live hosts for vulnerabilities and misconfigurations (nuclei)
6. Scans discovered JS files for leaked API keys, tokens, and secrets
7. Generates summary reports (`report.md`, `report.json`, and severity-colored `report.html`)
8. Sends optional completion alerts via Discord/Slack webhooks

## Requirements

- Python 3.8+ (no extra Python packages needed for the core flow)
- [`subfinder`](https://github.com/projectdiscovery/subfinder/releases) and [`httpx`](https://github.com/projectdiscovery/httpx/releases) — required
- [`naabu`](https://github.com/projectdiscovery/naabu/releases) — optional, for `--ports`
- [`nuclei`](https://github.com/projectdiscovery/nuclei/releases) — optional, for `--vuln`
- [`gau`](https://github.com/lc/gau) — optional, for `--urls` and `--secrets`
- [`gowitness`](https://github.com/sensepost/gowitness/releases) — optional, for `--screenshots`

Every new stage degrades gracefully: if a tool isn't installed, reconflow prints a warning and skips that stage instead of crashing.

Check your tools:

```bash
subfinder -version
httpx -version
```

## Install

```bash
git clone https://github.com/ErenYeager1836/reconflow.git
cd reconflow
```

## Usage

```bash
python reconflow_v2.py -d example.com --full --notify https://discord.com/api/webhooks/...
```

| Option | Description |
| --- | --- |
| `-d`, `--domain` | Target domain (required) |
| `-o`, `--output` | Output folder (default: `output`) |
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
| `--full` | Shortcut for `--ports --urls --vuln --secrets --html` |
| `--html` | Also build a severity-colored HTML report (`report.html`) |
| `--notify URL` | Post a run summary to a Discord/Slack-compatible webhook on finish |

## Example output

```
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
[+] HTML report saved to output\example.com\report.html
[+] Report saved to output\example.com\report.md
```

Files created in `output/<domain>/`:

```
subdomains.txt   all discovered subdomains
live.txt         live hosts with status code, title, tech
urls.txt         collected URLs (when using --urls or --full)
params.txt       unique query parameters (when using --urls or --full)
ports.json       open port mappings (when using --ports or --full)
vulns.json       nuclei vulnerability findings (when using --vuln or --full)
secrets.json     extracted secret matches (when using --secrets or --full)
report.md        summary Markdown report
report.json      structured JSON report (when using --json)
report.html      severity-colored HTML dashboard (when using --html or --full)
screenshots/     captured screenshots of live hosts (when using --screenshots)
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
- [ ] Save results as they come in (streaming / resumable runs)
- [ ] Config file for API keys & default flags (reconflow.yaml)
- [ ] Directory/endpoint fuzzing (ffuf integration)
- [ ] Docker image for zero-install usage

## Contributing

Contributions are welcome. Look for issues labelled `good first issue`.

## License

MIT
