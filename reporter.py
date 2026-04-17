# reporter.py
# handles all output — builds the final report dict, writes JSON, prints terminal summary
# called at the end of main.py after parsing and IOC aggregation are done
# Isaiah

import json
import sys
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def build_report(entries, ioc_summary):
    """
    assembles the final report dict from parsed entries and the global IOC summary
    """
    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(entries),
            "total_iocs": sum(len(v) for v in ioc_summary.values()),
        },
        "ioc_summary": ioc_summary,
        "entries": entries,
    }


def write_report(report, output_path=None, iocs_only=False):
    """
    writes the report to a file or stdout as JSON
    if iocs_only is True, strips the entries list from the output
    """
    if iocs_only:
        out = {
            "meta": report["meta"],
            "ioc_summary": report["ioc_summary"],
        }
    else:
        out = report

    serialized = json.dumps(out, indent=2, default=str)

    if output_path:
        with open(output_path, "w") as f:
            f.write(serialized)
        console.print(f"[green][+][/green] report written to [bold]{output_path}[/bold]")
    else:
        print(serialized)


def print_summary(entries, global_iocs, fmt, filepath):
    """
    prints the rich terminal summary — scan info panel, IOC table, suspicious events table
    called regardless of whether output is going to file or stdout
    """
    flagged = [e for e in entries if e.get("flags")]
    total_iocs = sum(len(v) for v in global_iocs.items() if isinstance(v, (list, set)))

    # scan info panel
    console.print(
        Panel(
            f"[bold]file:[/bold] {filepath}\n"
            f"[bold]format:[/bold] {fmt}\n"
            f"[bold]entries parsed:[/bold] {len(entries)}\n"
            f"[bold]entries flagged:[/bold] {len(flagged)}\n"
            f"[bold]unique IOCs:[/bold] {sum(len(v) for v in global_iocs.values())}",
            title="scan info",
            border_style="cyan",
        )
    )

    # IOC summary table
    if global_iocs:
        ioc_table = Table(title="extracted IOCs", border_style="dim")
        ioc_table.add_column("type", style="cyan", no_wrap=True)
        ioc_table.add_column("count", justify="right")
        ioc_table.add_column("values")

        for ioc_type, values in global_iocs.items():
            val_list = sorted(list(values))
            display = ", ".join(val_list[:5])
            if len(val_list) > 5:
                display += f" ... (+{len(val_list) - 5} more)"
            ioc_table.add_row(ioc_type, str(len(val_list)), display)

        console.print(ioc_table)
    else:
        console.print("[dim]no IOCs extracted[/dim]")

    # suspicious events table
    if flagged:
        flag_table = Table(title="suspicious events", border_style="red")
        flag_table.add_column("timestamp", style="dim", no_wrap=True)
        flag_table.add_column("user")
        flag_table.add_column("source_ip")
        flag_table.add_column("flags", style="red")

        for entry in flagged[:25]:  # cap at 25 to keep terminal readable
            flag_table.add_row(
                str(entry.get("timestamp") or ""),
                str(entry.get("user") or ""),
                str(entry.get("source_ip") or ""),
                ", ".join(entry.get("flags", [])),
            )

        if len(flagged) > 25:
            console.print(f"[dim]... and {len(flagged) - 25} more flagged entries (see full report)[/dim]")

        console.print(flag_table)
    else:
        console.print("[dim]no suspicious patterns matched[/dim]")
