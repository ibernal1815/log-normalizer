# log-normalizer / ioc-extractor

> **A CLI tool for parsing, normalizing, and extracting IOCs from Windows Event Logs, syslog, and auth.log files.**

Built for my home lab as part of learning detection engineering and SOC analysis workflows. The idea was simple: every investigation involves digging through raw logs in different formats, so I wanted a tool that could ingest them all and spit out something consistent I could actually work with.

---

## background / why i built this

When I was working through attack scenarios in my Sysmon lab, I kept running into the same problem — I had logs in three different formats (EVTX from Windows, auth.log from my Ubuntu VMs, syslog from pfSense) and no clean way to compare them. I'd either grep through them manually or export to a SIEM, which was overkill for quick triage.

So I wrote this. It reads any of those formats, normalizes every entry into the same JSON schema, and pulls out IOCs automatically. That way I can pipe the output into jq, feed it into Wazuh, or write Sigma rules against it without caring what the original format was.

---

## what it does

- parses `.evtx` (Windows Event Log), `syslog`, and `auth.log` files
- auto-detects the format from filename + content — or you can specify it manually
- normalizes every entry into a consistent schema:

```json
{
  "timestamp":      "2024-01-15T03:22:11",
  "source_ip":      "198.51.100.42",
  "destination_ip": null,
  "user":           "root",
  "event_id":       "4625",
  "action":         "Failed logon",
  "raw":            "Jan 15 03:22:11 server sshd[1842]: Failed password for root from 198.51.100.42",
  "iocs":           { "ipv4": ["198.51.100.42"] },
  "flags":          ["Failed SSH password"]
}
```

- extracts IOCs per entry and globally: IPv4, IPv6, domains, MD5/SHA1/SHA256, file paths
- flags suspicious patterns — Windows event IDs (4625, 4672, 7045, 1102, etc.) and Linux auth patterns (failed passwords, root logins, sudo commands)
- outputs a full JSON report: normalized entries + deduplicated IOC summary
- prints a color-coded terminal summary via `rich`

---

## project layout

```
log-normalizer/
│
├── main.py             # CLI entry point — arg parsing and orchestration
├── detector.py         # auto-detects log format from filename + content sample
├── parsers.py          # three parsers: parse_evtx, parse_syslog, parse_auth
├── ioc_extractor.py    # IOC regex extraction + merge/finalize helpers
├── patterns.py         # all regex patterns, suspicious event IDs, Linux flag patterns
├── reporter.py         # JSON report builder + rich terminal output
│
├── tests/
│   ├── test_ioc_extractor.py   # unit tests for IOC extraction logic
│   ├── test_detector.py        # unit tests for format detection
│   ├── test_parsers.py         # integration tests for each parser
│   └── samples/
│       ├── sample_auth.log     # sample auth.log with known IOCs baked in
│       ├── sample_syslog.log   # sample syslog with known IOCs baked in
│       └── sample_report.json  # example output for reference
│
├── README.md
├── TUTORIAL.md
└── .gitignore
```

---

## requirements

- Python 3.8+
- `rich` — terminal formatting
- `python-evtx` — only needed for `.evtx` parsing, optional otherwise

```bash
pip install rich python-evtx
```

---

## quick start

```bash
# clone the repo
git clone https://github.com/yourusername/log-normalizer.git
cd log-normalizer

# install dependencies
pip install rich python-evtx

# try it immediately with the included sample files
python main.py --input tests/samples/sample_auth.log --format auth
python main.py --input tests/samples/sample_syslog.log --output report.json
```

---

## usage

```bash
python main.py --input <file> [--format <fmt>] [--output <file>] [--iocs-only]
```

### flags

| flag | short | description |
|------|-------|-------------|
| `--input` | `-i` | path to the log file *(required)* |
| `--format` | `-f` | `auto` *(default)*, `evtx`, `syslog`, `auth` |
| `--output` | `-o` | write JSON to this file *(default: stdout)* |
| `--iocs-only` | — | only output the IOC summary section |

### examples

```bash
# windows event log — auto-detected, full report saved to file
python main.py --input Security.evtx --output report.json

# auth.log — explicit format, IOC summary only
python main.py --input /var/log/auth.log --format auth --iocs-only

# syslog — print JSON to stdout + terminal summary
python main.py --input /var/log/syslog

# pipe IOC summary into jq to filter just IPs
python main.py --input auth.log --iocs-only | jq '.ioc_summary.ipv4'
```

---

## output format

```json
{
  "meta": {
    "generated_at":  "2024-01-15T04:00:00",
    "total_entries": 847,
    "total_iocs":    23
  },
  "ioc_summary": {
    "ipv4":    ["185.220.101.5", "198.51.100.42"],
    "domain":  ["malicious.example.com"],
    "sha1":    ["3395856ce81f2b7382dee72602f798b642f14d0"]
  },
  "entries": [ { ... }, { ... } ]
}
```

`ioc_summary` is deduplicated across all entries. `entries` contains every log line, including ones with no IOCs.

---

## suspicious patterns flagged

### Windows Event IDs

| ID | Description |
|----|-------------|
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials (PtH indicator) |
| 4672 | Special privileges assigned to new logon |
| 4698 | Scheduled task created |
| 4720 | New user account created |
| 4728 | Member added to global privileged group |
| 4732 | Member added to local Administrators |
| 7045 | New service installed |
| 1102 | Security audit log cleared |
| 4719 | System audit policy changed |

### Linux auth / syslog

- Failed SSH password attempts
- PAM authentication failures
- `sudo` command execution
- New user added (`useradd` / `adduser`)
- Invalid username login attempts
- Direct root login
- Root session opened
- Public key auth accepted (useful for baselining normal behavior)

---

## ioc extraction notes

**Hash collision prevention** — SHA256 (64 chars) is extracted first. Those characters get scrubbed from the string before looking for SHA1 (40 chars), then MD5 (32 chars). Without this a SHA256 hash would match all three patterns since it contains a 40-char and 32-char substring.

**IP filtering** — loopback (`127.x`), unroutable (`0.0.0.x`), and broadcast (`255.255.x`) addresses are dropped automatically since they're never real IOCs.

**Domain regex** — matches against a hardcoded TLD list. Not exhaustive but covers what realistically shows up in logs and avoids pulling random hex strings or hostnames.

**Syslog year** — syslog RFC 3164 format doesn't include the year. The parser assumes the current year, which is fine for recent logs.

---

## running the tests

```bash
# all tests
python -m pytest tests/ -v

# just IOC extractor unit tests
python -m pytest tests/test_ioc_extractor.py -v

# just parser integration tests
python -m pytest tests/test_parsers.py -v
```

See `TUTORIAL.md` for a full walkthrough including what to look for in the output.

---

## how it fits into a real SOC workflow

This isn't a SIEM replacement — it's a quick triage and pre-processing tool. Specific use cases:

- **First look at a suspicious log file** — pipe it through, immediately see flagged events and extracted IOCs without spinning up anything heavy
- **IOC pivot** — extract all IPs/domains/hashes from a log set and check them against threat intel manually or via VirusTotal
- **Detection rule dev** — normalize logs first, then write Sigma rules against the consistent schema rather than against each raw format separately
- **Lab scenarios** — I run attack scenarios in my Sysmon lab (Kali vs Windows 11) and use this to process the resulting logs before writing detection notes

---

## stack

Python 3 · `rich` · `python-evtx` · `argparse` · `re` · `json` · `unittest`
