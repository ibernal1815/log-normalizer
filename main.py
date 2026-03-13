#!/usr/bin/env python3
# main.py - entry point for the log normalizer / IOC extractor
#
# runs from the command line, calls into the other modules to do the actual work
# started this as a one-file script but split it up when it got too long to navigate
#
# usage:
#   python main.py --input Security.evtx --output report.json
#   python main.py --input /var/log/auth.log --format auth --iocs-only
#   python main.py --input syslog.log
#
# Isaiah
# CIT 499 / personal home lab project

import argparse
import os
import sys

from rich.console import Console

from detector import detect_format
from ioc_extractor import merge_iocs, finalize_iocs
from parsers import parse_evtx, parse_syslog, parse_auth
from reporter import build_report, write_report, print_summary

console = Console()


def get_args():
    p = argparse.ArgumentParser(
        prog="log-normalizer",
        description="parses .evtx / syslog / auth.log files, extracts IOCs, outputs JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python main.py --input Security.evtx --output report.json
  python main.py --input /var/log/auth.log --format auth --iocs-only
  python main.py --input syslog.log --format syslog --output iocs.json
        """
    )
    p.add_argument("--input",  "-i", required=True, metavar="FILE",
                   help="log file to parse")
    p.add_argument("--format", "-f", default="auto",
                   choices=["auto", "evtx", "syslog", "auth"],
                   help="log format (default: auto-detect)")
    p.add_argument("--output", "-o", metavar="FILE",
                   help="write JSON report here (default: stdout)")
    p.add_argument("--iocs-only", action="store_true",
                   help="only output the IOC summary, skip the full entry list")
    return p.parse_args()


def main():
    args = get_args()

    # make sure the file actually exists before doing anything
    if not os.path.isfile(args.input):
        console.print(f"[red][!][/red] file not found: {args.input}")
        sys.exit(1)

    # auto-detect or use whatever the user specified
    fmt = args.format
    if fmt == "auto":
        fmt = detect_format(args.input)
        console.print(f"[dim]detected format:[/dim] [bold]{fmt}[/bold]")

    console.print(f"[cyan]*[/cyan] parsing [bold]{args.input}[/bold]...")

    # dispatch to the right parser
    if fmt == "evtx":
        entries = parse_evtx(args.input)
    elif fmt == "auth":
        entries = parse_auth(args.input)
    else:
        entries = parse_syslog(args.input)

    console.print(f"[dim]  parsed {len(entries)} entries[/dim]")

    # aggregate IOCs across all entries into one global dict
    global_iocs = {}
    for entry in entries:
        merge_iocs(global_iocs, entry.get("iocs", {}))

    ioc_summary = finalize_iocs(global_iocs)

    # build and write the report
    report = build_report(entries, ioc_summary)
    write_report(report, output_path=args.output, iocs_only=args.iocs_only)

    # print the terminal summary regardless of output mode
    print_summary(entries, global_iocs, fmt, args.input)


if __name__ == "__main__":
    main()
