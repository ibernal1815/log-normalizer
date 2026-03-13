# detector.py
# figures out what log format a file is based on the extension and content
# keeping this in its own file since the logic was getting messy inside main
# Isaiah

import re
from pathlib import Path


def detect_format(filepath):
    """
    tries to figure out if the file is evtx, auth.log, or generic syslog
    checks extension first, then falls back to sampling the first 15 lines

    returns one of: "evtx", "auth", "syslog"
    """
    path = Path(filepath)

    # easy case - windows event log has its own extension
    if path.suffix.lower() == ".evtx":
        return "evtx"

    # read a sample of the file to check content
    try:
        with open(filepath, "r", errors="replace") as f:
            lines = [f.readline() for _ in range(15)]
        sample = "".join(lines)
    except Exception:
        return "syslog"  # default fallback

    fname = path.name.lower()

    # auth.log detection: filename has to say auth/secure/login AND
    # the content has to look like auth stuff. avoids false positives
    # on a random syslog that happens to have one "sshd" line
    auth_name = any(n in fname for n in ("auth", "secure", "login"))
    auth_content = bool(re.search(r'\b(sshd|pam_unix|sudo|su)\b', sample))

    if auth_name and auth_content:
        return "auth"

    # syslog: check for the RFC 3164 timestamp at the start of a line
    # "Jan  5 03:22:11" or "Jan 15 03:22:11"
    if re.search(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', sample, re.MULTILINE):
        if auth_name:
            return "auth"
        return "syslog"

    # if nothing matched, syslog is a reasonable guess for text logs
    return "syslog"
