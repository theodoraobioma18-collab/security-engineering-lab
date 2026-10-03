# IOC Enrichment Tool

Automates threat intel lookups for indicators of compromise (IOCs). Feed it a mixed list of IPs and file hashes; it classifies each one, queries the right source, and produces an analyst-ready CSV report.

## Why

During triage, analysts manually paste indicators into AbuseIPDB and VirusTotal one at a time and copy results into a ticket or spreadsheet. A manual lookup took me about **70 seconds per indicator**. This tool processed the 8-indicator sample set in ** 33.7947811 seconds**, unattended, with consistent verdicts and a report ready to attach to a ticket.

## Features

- **Auto-classification:** detects public IPs, private IPs, MD5, SHA-1, and SHA-256 hashes
- **Source routing:** IPs → AbuseIPDB, file hashes → VirusTotal
- **Rate limiting:** throttles VirusTotal calls to stay within the free tier (4/min)
- **Retry on HTTP 429:** waits and retries when rate-limited; other errors fail fast
- **Error isolation:** one failed lookup is logged as `ERROR` and the batch continues
- **Deduplication:** repeated indicators are only looked up once
- **CSV output:** Excel-friendly report plus a verdict summary in the terminal

## How it works

```
IOC file ──► read + dedupe ──► detect type ──┬── public IP ──► AbuseIPDB
                                             ├── hash ───────► VirusTotal
                                             ├── private IP ─► skipped (never sent externally)
                                             └── unknown ────► skipped
                                                    │
                                                    ▼
                                         results.csv + summary
```

| File | Purpose |
| --- | --- |
| `enrich.py` | Main tool: reads IOCs, routes lookups, handles rate limits/errors, writes CSV |
| `ioc_types.py` | IOC classification (`ipaddress` module + regex for hashes) |
| `check_ip.py` | AbuseIPDB lookup; also runs standalone for a single IP |
| `check_hash.py` | VirusTotal lookup; also runs standalone for a single hash |
| `sample_iocs.txt` | Test set covering every IOC type, including edge cases |

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env      # then add your own API keys to .env
```

Free API keys: [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/).

## Usage

```powershell
# Full enrichment
python enrichment\enrich.py -i enrichment\sample_iocs.txt -o results.csv

# Single lookups
python enrichment\check_ip.py 8.8.8.8
python enrichment\check_hash.py 44d88612fea8a8f36de82e1278abb02f

# Options
python enrichment\enrich.py --help
```

## Sample output

```
[1/8] CLEAN          ip          8.8.8.8
[2/8] CLEAN          ip          1.1.1.1
[3/8] MALICIOUS      ip          199.45.155.38
[4/8] SKIPPED        private_ip  192.168.1.10
[5/8] MALICIOUS      md5         44d88612fea8a8f36de82e1278abb02f
[6/8] MALICIOUS      sha1        3395856ce81f2b7382dee72602f798b642f14140
[7/8] MALICIOUS      sha256      275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
[8/8] SKIPPED        unknown     not-an-ioc

Report written to results.csv
  MALICIOUS      4
  CLEAN          2
  SKIPPED        2
```

## Verdict logic

| Source | MALICIOUS | SUSPICIOUS | Otherwise |
| --- | --- | --- | --- |
| AbuseIPDB | score ≥ 75 | score ≥ 25 | CLEAN |
| VirusTotal | ≥ 5 engines | 1–4 engines | NO DETECTIONS / NOT FOUND |

Hashes use **NO DETECTIONS** rather than "clean" on purpose: zero detections does not mean a file is safe (new or targeted malware often has none). Reputation scores are signals, not verdicts. For example, `199.45.155.38` scores 100/100 but belongs to Censys, a research scanner rather than a targeted attacker.

## Security design decisions

- **No secrets in code:** API keys load from a git-ignored `.env`; `.env.example` documents what is required. Ignore rules were verified with `git check-ignore` before any keys were added.
- **Keys in headers, not URLs:** keeps credentials out of logs and error messages.
- **Private IPs are never sent externally:** avoids leaking internal network details to third parties.
- **Lookup only, never upload:** hashes are queried; files are never submitted to VirusTotal.
- **Output is git-ignored:** `results*.csv` may contain investigation data and stays out of version control.
- **Network timeouts on every request:** the tool never hangs indefinitely.

## Known limitations and future work

- Deduplicates by string, not by file: MD5/SHA-1/SHA-256 of the same file are counted separately
- No domain or URL support yet
- Single-threaded; large lists are bounded by the VirusTotal free-tier rate limit
- Planned: reuse this lookup logic in a Microsoft Sentinel playbook to auto-enrich incidents (Week 3)