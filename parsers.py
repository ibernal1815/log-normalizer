# parsers.py
# one parser per log type: evtx, syslog, auth.log
# each one returns a list of normalized entry dicts
#
# the normalized schema is:
#   timestamp, source_ip, destination_ip, user, event_id, action, raw, iocs, flags
#
# i set everything to None by default so the JSON output is consistent
# even when a field cant be extracted from a given log format
# Isaiah

import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

from ioc_extractor import extract_iocs
from patterns import SUSPICIOUS_WIN_EVENTS, SUSPICIOUS_LINUX_PATTERNS

# windows event log - optional dependency
try:
    import Evtx.Evtx as evtx
    EVTX_OK = True
except ImportError:
    EVTX_OK = False

# syslog timestamp format - "Jan  5 03:22:11" (note the double space for single digit days)
SYSLOG_LINE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$'
)


def _blank_entry():
    # helper so i dont have to type this out every time
    return {
        "timestamp":      None,
        "source_ip":      None,
        "destination_ip": None,
        "user":           None,
        "event_id":       None,
        "action":         None,
        "raw":            "",
        "iocs":           {},
        "flags":          [],
    }


def _check_linux_flags(msg):
    # run the message through all our suspicious patterns
    # returns a list of matching flag strings
    hits = []
    for pattern, label in SUSPICIOUS_LINUX_PATTERNS:
        if pattern.search(msg):
            hits.append(label)
    return hits


# -----------------------------------------------------------------------
# EVTX PARSER
# -----------------------------------------------------------------------

def parse_evtx(filepath):
    """
    parses a windows .evtx file using python-evtx
    each record is XML so we pull fields out by namespace + tag name

    the windows event log XML namespace is a mouthful:
    http://schemas.microsoft.com/win/2004/08/events/event
    """
    if not EVTX_OK:
        print("[!] python-evtx not installed. run: pip install python-evtx")
        sys.exit(1)

    NS = "http://schemas.microsoft.com/win/2004/08/events/event"
    entries = []

    with evtx.Evtx(filepath) as log:
        for record in log.records():
            entry = _blank_entry()
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)

                # grab EventID and timestamp from <System>
                sys_el = root.find(f"{{{NS}}}System")
                if sys_el is not None:
                    eid = sys_el.find(f"{{{NS}}}EventID")
                    if eid is not None:
                        entry["event_id"] = eid.text

                    tc = sys_el.find(f"{{{NS}}}TimeCreated")
                    if tc is not None:
                        entry["timestamp"] = tc.get("SystemTime")

                # pull key=value pairs out of <EventData>
                ev_data = root.find(f"{{{NS}}}EventData")
                fields = {}
                if ev_data is not None:
                    for d in ev_data.findall(f"{{{NS}}}Data"):
                        name = d.get("Name", "")
                        val = d.text or ""
                        if name:
                            fields[name] = val

                # these field names vary by event ID but these cover most cases
                entry["user"]      = fields.get("SubjectUserName") or fields.get("TargetUserName")
                entry["source_ip"] = fields.get("IpAddress") or fields.get("WorkstationName")

                eid_str = entry["event_id"]
                if eid_str in SUSPICIOUS_WIN_EVENTS:
                    entry["action"] = SUSPICIOUS_WIN_EVENTS[eid_str]
                    entry["flags"].append(SUSPICIOUS_WIN_EVENTS[eid_str])
                else:
                    entry["action"] = f"Event {eid_str}"

                # truncate raw XML so the JSON doesnt get insane
                entry["raw"] = xml_str[:600]
                entry["iocs"] = extract_iocs(xml_str + " " + " ".join(fields.values()))

            except Exception as err:
                entry["raw"] = f"[parse error] {err}"

            entries.append(entry)

    return entries


# -----------------------------------------------------------------------
# SYSLOG PARSER
# -----------------------------------------------------------------------

def parse_syslog(filepath):
    """
    handles standard syslog (RFC 3164 style)
    format: Mon DD HH:MM:SS hostname process[pid]: message

    syslog doesnt include the year in the timestamp which is annoying
    so we just assume current year - close enough for lab purposes
    """
    entries = []
    year = datetime.now().year

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue

            entry = _blank_entry()
            entry["raw"] = line

            m = SYSLOG_LINE.match(line)
            if m:
                g = m.groupdict()

                # build a timestamp we can actually parse
                ts_str = f"{g['month']} {g['day']} {year} {g['time']}"
                try:
                    entry["timestamp"] = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S").isoformat()
                except ValueError:
                    entry["timestamp"] = ts_str  # just store it raw if parsing fails

                msg = g["msg"]
                entry["action"] = g["proc"].strip()
                entry["flags"]  = _check_linux_flags(msg)

                # look for source IP in "from X.X.X.X" or "rhost=X.X.X.X"
                ip_m = re.search(r'(?:from|rhost=)\s*(\d{1,3}(?:\.\d{1,3}){3})', msg)
                if ip_m:
                    entry["source_ip"] = ip_m.group(1)

                # user is often "for user X" or just "for X" in syslog
                user_m = re.search(r'(?:for user|user=|for)\s+(\S+)', msg, re.I)
                if user_m:
                    entry["user"] = user_m.group(1)

            entry["iocs"] = extract_iocs(line)
            entries.append(entry)

    return entries


# -----------------------------------------------------------------------
# AUTH.LOG PARSER
# -----------------------------------------------------------------------

def parse_auth(filepath):
    """
    parses linux auth.log (and /var/log/secure on RHEL-based systems)
    structure is basically the same as syslog but the messages are
    always auth-related so we can do more specific field extraction

    i tested this against auth.log samples from my ubuntu VM in the home lab
    """
    entries = []
    year = datetime.now().year

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue

            entry = _blank_entry()
            entry["raw"] = line

            m = SYSLOG_LINE.match(line)
            if m:
                g = m.groupdict()

                ts_str = f"{g['month']} {g['day']} {year} {g['time']}"
                try:
                    entry["timestamp"] = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S").isoformat()
                except ValueError:
                    entry["timestamp"] = ts_str

                msg  = g["msg"]
                proc = g["proc"].strip()

                entry["action"] = proc
                entry["flags"]  = _check_linux_flags(msg)

                # SSH logs the attacking IP as "from X.X.X.X"
                ip_m = re.search(r'(?:from|rhost=)\s*(\d{1,3}(?:\.\d{1,3}){3})', msg)
                if ip_m:
                    entry["source_ip"] = ip_m.group(1)

                # auth.log has a few different user field formats
                # "for user X", "for invalid user X", "for X" etc
                user_m = re.search(
                    r'for(?:\s+invalid)?\s+user\s+(\w+)|for\s+(\w+)\s+from', msg, re.I
                )
                if user_m:
                    # one of the two groups will match
                    entry["user"] = user_m.group(1) or user_m.group(2)

                # port number as a proxy for destination info
                port_m = re.search(r'\bport\s+(\d+)', msg, re.I)
                if port_m:
                    entry["destination_ip"] = f":{port_m.group(1)}"

            entry["iocs"] = extract_iocs(line)
            entries.append(entry)

    return entries
