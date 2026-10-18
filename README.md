# reconflow

[![PyPI](https://img.shields.io/pypi/v/reconflow)](https://pypi.org/project/reconflow/)

Recon for bug bounty hunters that tells you **what changed** since your last scan.

```bash
pip install reconflow
```

`reconflow` chains [subfinder](https://github.com/projectdiscovery/subfinder) and [httpx](https://github.com/projectdiscovery/httpx) into one command, filters out wildcard DNS noise, saves a snapshot of every run, and lets you `diff` any two runs to see new subdomains, newly live hosts, and changed responses.

> **Use responsibly.** Only scan domains you own or that are explicitly in scope for a bug bounty / pentest program you are authorized to test.

## Features

- **`scan`**: finds subdomains, drops wildcard DNS false positives (including rotating IP pools), probes live hosts for status code, title and technologies, and writes a Markdown report
- **`diff`**: compares your two most recent scans of a domain and highlights what's new
- **Scan history**: every scan saves a structured snapshot, so nothing is overwritten
- **Cron-friendly**: `diff` exits `1` when something changed and `0` when nothing did
- No Python dependencies beyond the standard library

## Requirements

- Python 3.8+
- [`subfinder`](https://github.com/projectdiscovery/subfinder/releases) and [`httpx`](https://github.com/projectdiscovery/httpx/releases) (ProjectDiscovery's Go versions) on your `PATH`
- [`gowitness`](https://github.com/sensepost/gowitness/releases) (optional, only for `--screenshots`)

> **Note:** `httpx` must be ProjectDiscovery's tool, not the Python `httpx` library. On Kali/Debian/Ubuntu it is often packaged as `httpx-toolkit`. reconflow checks for both names and verifies the binary.

Check your tools:

```
subfinder -version
httpx -version
```

## Install

From PyPI:

```
pip install reconflow
```

From source:

```
git clone https://github.com/ErenYeager1836/reconflow.git
cd reconflow
pip install -e .
```

## Usage

```
reconflow scan example.com
reconflow diff example.com
```

You can also run it as a module: `python -m reconflow scan example.com`

### `scan`

| Option | Description |
| --- | --- |
| `domain` | Target domain (required, must be in scope) |
| `-o`, `--output` | Output folder (default: `output`) |
| `--threads` | Number of threads for probing (default: 10) |
| `--timeout` | Timeout in seconds for probing (default: 5) |
| `--keep-wildcard` | Warn about wildcard DNS but don't filter wildcard results |
| `--json` | Also write structured results to `report.json` |
| `--screenshots` | Capture screenshots of live hosts (requires gowitness) |

### `diff`

| Option | Description |
| --- | --- |
| `domain` | Target domain to compare runs for (required) |
| `-o`, `--output` | Output folder (default: `output`) |
| `--json` | Print the comparison as JSON |

`diff` needs at least two saved scans of the same domain. Run `scan` twice first.

## Track changes with `diff`

Most recon tools tell you what exists. reconflow also tells you what changed. New subdomains and newly live hosts are often the least-tested parts of a target.

Example output (illustrative):

```
[*] Recon diff: 2026-10-18_185218 -> 2026-10-18_190412
============================================================
[+] NEW SUBDOMAINS (2):
    + beta.example.com
    + staging-api.example.com
[+] NEWLY LIVE HOSTS (1):
    + https://beta.example.com [200] [Beta Portal] [Nginx, React]
[*] CHANGED HOSTS (1):
    ~ https://admin.example.com
        status: 403 -> 200
        title: 'Forbidden' -> 'Admin Login'
        tech: ['Apache'] -> ['Apache', 'PHP']
[-] Removed subdomains (1) [informational]:
    - old.example.com
============================================================
```

Removed subdomains are informational only, because subfinder's sources can return slightly different results between runs.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No changes found (or not enough history to compare) |
| `1` | Changes were detected |

### Run it on a schedule

```
# Every 6 hours: rescan and log changes
0 */6 * * * reconflow scan example.com && reconflow diff example.com >> ~/recon-changes.log
```

## Output

Files are saved under `output/<domain>/`:

```
subdomains.txt      all discovered subdomains
live.txt            live hosts with status code, title, tech
report.md           summary report
report.json         structured report (with --json)
screenshots/        screenshots of live hosts (with --screenshots)
runs/<run_id>/      snapshot of each scan, used by diff
```

## Known limitations

- **Wildcard DNS domains** return many fake "live" hosts that all point to the same server. reconflow detects them and filters those hosts (use `--keep-wildcard` to disable).
- Discovery depends on subfinder's sources, so results can vary between runs.

## Roadmap

- [x] Subdomain discovery and live host probing
- [x] Wildcard DNS detection (including rotating IP pools)
- [x] `--threads` and `--timeout` options
- [x] JSON report output
- [x] Screenshots of live hosts
- [x] Scan history and `reconflow diff`
- [ ] `reconflow scope`: check targets against program scope
- [ ] `reconflow report`: regenerate reports from saved scans
- [ ] `--notify`: Discord/Slack webhook alerts for diff results
- [ ] Save results as they come in

## Contributing

Contributions are welcome. Look for issues labelled `good first issue`. Run the tests with:

```
python -m unittest discover tests -v
```

## License

MIT
