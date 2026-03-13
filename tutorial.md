# TUTORIAL.md — log-normalizer / ioc-extractor walkthrough

This walks through the full tool from install to actual use. I wrote it mostly for myself to remember what everything does after coming back to this after a break, but also because it's the kind of doc I wish more projects had.

---

## table of contents

1. [what you need](#1-what-you-need)
2. [install and setup](#2-install-and-setup)
3. [project structure explained](#3-project-structure-explained)
4. [your first run — auth.log](#4-your-first-run--authlog)
5. [parsing syslog](#5-parsing-syslog)
6. [understanding the output](#6-understanding-the-output)
7. [using --iocs-only and jq](#7-using---iocs-only-and-jq)
8. [parsing windows evtx files](#8-parsing-windows-evtx-files)
9. [how the IOC extraction works](#9-how-the-ioc-extraction-works)
10. [how suspicious pattern detection works](#10-how-suspicious-pattern-detection-works)
11. [running the tests](#11-running-the-tests)
12. [common errors and fixes](#12-common-errors-and-fixes)
13. [practical use cases](#13-practical-use-cases)

---

## 1. what you need

- Python 3.8 or newer (check with `python --version` or `python3 --version`)
- pip
- a terminal
- optionally: `jq` for filtering JSON output (`apt install jq` or `brew install jq`)

The tool runs on Linux, macOS, and Windows (WSL works fine for the Linux log formats).

---

## 2. install and setup

```bash
# clone the repo
git clone https://github.com/yourusername/log-normalizer.git
cd log-normalizer

# install the two required libraries
pip install rich python-evtx

# verify everything imported correctly
python -c "from rich.console import Console; import Evtx.Evtx; print('good')"
```

If the import check prints `good`, you're set.

If `python-evtx` fails to install (it sometimes does on Windows), that's fine — you only need it if you're parsing `.evtx` files. Everything else works without it.

---

## 3. project structure explained

Here's what each file actually does and how they connect:

```
main.py
  │
  ├── detector.py        ← called first to figure out what format the file is
  │
  ├── parsers.py         ← called based on detected/specified format
  │     ├── imports ioc_extractor.py   (IOC extraction happens per-line inside the parser)
  │     └── imports patterns.py        (regex patterns + suspicious event ID lists)
  │
  ├── ioc_extractor.py   ← also called by main.py to merge and finalize the global IOC set
  │     └── imports patterns.py
  │
  └── reporter.py        ← called at the end to write JSON and print the terminal summary
```

**main.py** is the only file you run directly. It parses CLI args, calls `detect_format()`, dispatches to the right parser, aggregates IOCs across all entries, builds the report, and calls the reporter. About 50 lines, mostly orchestration.

**detector.py** checks the file extension first (`.evtx` is unambiguous), then reads the first 15 lines and looks for auth-related process names. Returns `"evtx"`, `"auth"`, or `"syslog"`.

**parsers.py** has three functions — `parse_evtx`, `parse_syslog`, `parse_auth`. Each one returns a list of normalized entry dicts following the same schema regardless of input format. That schema is the whole point of the tool.

**ioc_extractor.py** has one main function (`extract_iocs`) that takes a raw string and returns a dict of whatever IOC types it finds. It also has `merge_iocs` (called per-entry to build the global set) and `finalize_iocs` (converts sets to sorted lists before JSON serialization).

**patterns.py** is just constants — all the regex objects and the suspicious event ID dicts. Keeping it separate means you can tune detection without touching any logic.

**reporter.py** handles output. `build_report()` assembles the final dict. `write_report()` serializes to JSON. `print_summary()` renders the rich terminal output.

---

## 4. your first run — auth.log

The repo includes a sample auth.log in `tests/samples/` that simulates a brute force followed by a compromise. Let's use that.

```bash
python main.py --input tests/samples/sample_auth.log --format auth
```

You should see:
- a `scan info` panel showing the file, format, and entry count
- an `extracted IOCs` table showing IPv4 addresses and file paths found
- a red `suspicious events` table showing failed SSH attempts, root logins, sudo commands, and user creation

Now save it to a file:

```bash
python main.py --input tests/samples/sample_auth.log --format auth --output report.json
```

Open `report.json` — it has three sections: `meta`, `ioc_summary`, and `entries`. The entries list has one dict per log line.

---

## 5. parsing syslog

```bash
python main.py --input tests/samples/sample_syslog.log --output syslog_report.json
```

Notice it auto-detects `syslog` this time because the filename doesn't say "auth" or "secure".

The syslog sample has:
- a brute force from `45.33.32.156`
- an MD5 mismatch on `/usr/bin/sudo` — that's a real red flag in an investigation
- a connection from `scanner.shodan.io` (domain extracted)
- a SHA1 hash from a file integrity check line

All of these should show up in the terminal summary and the JSON.

---

## 6. understanding the output

Every entry in the `entries` array follows this exact schema:

```json
{
  "timestamp":      "2024-03-10T09:10:06",
  "source_ip":      "45.33.32.156",
  "destination_ip": null,
  "user":           "root",
  "event_id":       null,
  "action":         "sshd",
  "raw":            "Mar 10 09:10:06 fileserver sshd[3399]: Failed password for root from 45.33.32.156 port 22 ssh2",
  "iocs": {
    "ipv4": ["45.33.32.156"]
  },
  "flags": ["Failed SSH password"]
}
```

**What each field means:**

| field | description |
|-------|-------------|
| `timestamp` | ISO 8601 format, converted from whatever the log used |
| `source_ip` | extracted from "from X.X.X.X" or `IpAddress` field in EVTX |
| `destination_ip` | usually null for auth/syslog; set to `:port` if a port is mentioned |
| `user` | username targeted or acting — varies by event type |
| `event_id` | Windows Event ID if applicable, null for Linux logs |
| `action` | for Linux: process name (sshd, sudo, etc.). For Windows: event description |
| `raw` | the original log line, unmodified |
| `iocs` | dict of IOC type → list of extracted values for this specific entry |
| `flags` | list of suspicious pattern labels that matched this entry |

**The `ioc_summary` section** at the top of the report is deduplicated across all entries. If the same IP appears in 50 log lines, it only appears once in `ioc_summary`. The per-entry `iocs` field still shows it on each individual line.

---

## 7. using --iocs-only and jq

`--iocs-only` strips the full entries list and just returns the meta + deduplicated IOC summary:

```bash
python main.py --input tests/samples/sample_auth.log --format auth --iocs-only
```

This is much faster to eyeball when you just want to know what IPs were involved.

Combine it with `jq` to filter specific IOC types:

```bash
# just the IPv4 addresses
python main.py --input tests/samples/sample_auth.log --format auth --iocs-only | jq '.ioc_summary.ipv4'

# count of each IOC type
python main.py --input tests/samples/sample_auth.log --format auth --iocs-only | jq '.ioc_summary | keys'

# all IOCs as flat list (useful for pasting into VirusTotal bulk search)
python main.py --input tests/samples/sample_auth.log --format auth --iocs-only \
  | jq '[.ioc_summary | to_entries[] | .value[]] | .[]' -r
```

---

## 8. parsing windows evtx files

`.evtx` files require `python-evtx`. If you're running this on a Windows host or have exported event logs:

```bash
python main.py --input Security.evtx --output evtx_report.json
```

The format is auto-detected from the `.evtx` extension, so you don't need `--format evtx`.

The EVTX parser reads the XML structure of each record and pulls:
- `SystemTime` → `timestamp`
- `EventID` → `event_id`
- `SubjectUserName` or `TargetUserName` → `user`
- `IpAddress` or `WorkstationName` → `source_ip`

Any event ID in the suspicious list (4625, 4672, 7045, etc.) gets flagged automatically.

**Getting a Security.evtx from your Windows VM:**

In PowerShell (as admin):
```powershell
# copy the current security log somewhere accessible
wevtutil epl Security C:\Users\Public\Security.evtx
```

Then move it to your Linux machine and run it through the tool.

---

## 9. how the IOC extraction works

All the regex patterns live in `patterns.py`. The extraction function in `ioc_extractor.py` runs each pattern against the raw text and returns matches.

**Hash extraction order matters.**

SHA256 hashes are 64 hex chars. SHA1 are 40. MD5 are 32. The problem is that a SHA256 hash *contains* substrings that would match SHA1 and MD5 patterns.

So the extractor does this:

```
1. find all SHA256 matches (64 chars)
2. remove those characters from the working string
3. find all SHA1 matches (40 chars) in the scrubbed string
4. remove those
5. find all MD5 matches (32 chars) in what's left
```

Without this, a single SHA256 hash would appear in all three IOC categories, which would be wrong and annoying.

**IP filtering.**

Loopback (`127.x`), unroutable (`0.0.0.x`), and broadcast (`255.255.x`) addresses are dropped. They're never real IOCs — they're just noise from process startup logs, bind messages, etc.

**Domain matching.**

The domain regex only matches against a hardcoded TLD list (com, net, org, io, gov, etc.). This avoids pulling random tokens that happen to match the pattern. It's not exhaustive but covers what realistically shows up in auth/syslog/evtx logs.

---

## 10. how suspicious pattern detection works

**For Linux logs (auth/syslog):**

Each parsed log line's message gets checked against every pattern in `SUSPICIOUS_LINUX_PATTERNS` from `patterns.py`. If it matches, the label gets appended to that entry's `flags` list. Multiple patterns can match the same line (e.g., a root failed password line could hit both "Failed SSH password" and "Direct root login").

The patterns check things like:
- `Failed password` (case insensitive)
- `COMMAND=` (present in any sudo log line)
- `ROOT LOGIN`
- `session opened for user root`
- `useradd|adduser`
- `Invalid user`

**For Windows EVTX:**

The parser checks the Event ID against `SUSPICIOUS_WIN_EVENTS` dict. If it's in there, the description becomes both the `action` field and a `flags` entry.

Event IDs worth knowing:
- **4625** — failed logon. High volume = brute force. Single occurrence = lock your account.
- **4648** — logon with explicit credentials. Shows up with `runas`, pass-the-hash, and some legit admin tools.
- **4672** — special privileges assigned. Watch for this immediately after a 4624 (successful logon) — means the logged-in user has admin-level rights.
- **7045** — new service installed. Classic persistence mechanism. Should almost never appear on a production box unexpectedly.
- **1102** — audit log cleared. Someone's trying to cover tracks.

---

## 11. running the tests

```bash
# all 59 tests
python -m pytest tests/ -v

# just the unit tests for IOC extraction
python -m pytest tests/test_ioc_extractor.py -v

# just the format detector tests
python -m pytest tests/test_detector.py -v

# just the parser integration tests (runs against the sample files)
python -m pytest tests/test_parsers.py -v

# show print output during tests (useful for debugging)
python -m pytest tests/ -v -s
```

**What the tests cover:**

`test_ioc_extractor.py` — unit tests for each IOC type: basic extraction, deduplication, edge cases (empty string, very long line, loopback IP filtering, the SHA256/SHA1/MD5 collision prevention). These run without needing any log files.

`test_detector.py` — tests that the auto-detector returns the right format string for different filenames and content combinations. Uses `tempfile` to create fake log files with controlled content.

`test_parsers.py` — integration tests that run the full parsers against `tests/samples/sample_auth.log` and `tests/samples/sample_syslog.log`. Checks that specific IPs, hashes, domains, and flag labels appear in the output. Also tests edge cases like empty files and malformed lines.

**If a test fails:**

The test names are descriptive. `test_sha1_hash_extracted_from_kernel_line` failing means the SHA1 hash in the kernel log line isn't being extracted. Check `patterns.py` to verify the SHA1 regex, and check the sample file to make sure the hash is actually 40 hex characters.

---

## 12. common errors and fixes

**`ModuleNotFoundError: No module named 'rich'`**
```bash
pip install rich
```

**`ModuleNotFoundError: No module named 'Evtx'`**
```bash
pip install python-evtx
```
Only needed for `.evtx` files. You can use the tool without it for syslog/auth.

**`[!] file not found: your_file.log`**

The path you passed to `--input` doesn't exist or you're in the wrong directory. Try an absolute path.

**Format auto-detected as wrong type**

Use `--format` to specify it manually:
```bash
python main.py --input weird_named_log.txt --format auth
```

**JSON output has `null` everywhere**

Some log formats don't have all fields. `null` in the JSON just means that field couldn't be extracted from that line — it's expected. Lines that don't match the expected format at all still get their raw text stored.

**Timestamps look wrong (wrong year)**

Syslog doesn't include the year. The parser assumes the current year. If you're analyzing old logs, the year will be wrong in the output — this is a known limitation. For incident analysis of recent logs it's fine.

**Getting garbled output / encoding errors**

The parsers open files with `errors="replace"` which substitutes a placeholder character for invalid bytes. If you see `?` or similar in the raw field, that's why. The log file has non-UTF-8 bytes — usually fine to ignore for IOC extraction purposes.

---

## 13. practical use cases

**Triage a suspicious auth.log quickly:**
```bash
python main.py --input /var/log/auth.log --format auth --iocs-only
```
Immediately see all unique IPs and any domains that appeared in the log. Cross-reference the IPs against threat intel.

**Extract all IOCs from a log set and save them:**
```bash
python main.py --input /var/log/auth.log --format auth --iocs-only --output auth_iocs.json
python main.py --input /var/log/syslog --format syslog --iocs-only --output syslog_iocs.json
```

**Find all flagged events in a Windows event log:**
```bash
python main.py --input Security.evtx --output full_report.json
cat full_report.json | jq '.entries[] | select(.flags | length > 0) | {timestamp, user, source_ip, event_id, flags}'
```

**Count failed logins per IP:**
```bash
python main.py --input auth.log --format auth --output report.json
cat report.json | jq '
  [.entries[] | select(.flags[] | contains("Failed")) | .source_ip] 
  | group_by(.) 
  | map({ip: .[0], count: length}) 
  | sort_by(-.count)
'
```

**Feed into a Wazuh custom rule check:**
Normalize your log first, then write a Python script that reads the JSON and formats alerts for Wazuh's API — the consistent schema makes this straightforward since you don't have to write different parsers for each log format in your Wazuh rule.
