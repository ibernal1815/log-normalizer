# changelog

all notable changes to this project are documented here.

---

## v1.1.0 — 2026-04-17

### added
- `reporter.py` — extracted terminal output and JSON serialization into its own module
- `CHANGELOG.md` — version tracking

### fixed
- renamed `ioc-extractor.py` to `ioc_extractor.py` — hyphenated filenames break Python imports
- removed school project label from `main.py` header comment
- updated README project layout to match actual repo structure
- fixed clone URL in README and tutorial.md (was `yourusername`, now correct)
- clarified `tests/samples/` as the single location for sample files

### changed
- README code blocks now use 4-space indentation to prevent nested backtick rendering issues

---

## v1.0.0 — 2025-12-01

### initial release
- `main.py` CLI entry point with `--input`, `--format`, `--output`, `--iocs-only` flags
- `detector.py` — auto-detects evtx, syslog, and auth.log formats from filename and content
- `parsers.py` — three parsers normalizing all formats to a consistent JSON schema
- `ioc_extractor.py` — extracts IPv4, IPv6, domains, MD5/SHA1/SHA256, file paths per entry
- `patterns.py` — regex patterns, suspicious Windows event IDs, Linux auth flag patterns
- unit and integration test suite covering IOC extraction, format detection, and all three parsers
- sample log files for auth.log and syslog in `tests/samples/`
- `tutorial.md` — full walkthrough from install to practical SOC use cases
