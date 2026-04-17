# patterns.py
# all regex patterns and suspicious event ID lists
# kept separate so detection logic can be tuned without touching parsers
#
# Isaiah

import re

# --- IOC patterns ---

IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# covers full and compressed IPv6 addresses
IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}'
)

# only matches common TLDs to avoid pulling garbage tokens out of logs
DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|edu|gov|mil|io|co|uk|de|ru|cn|info|biz|xyz|'
    r'top|site|online|tech|app|dev|cloud|store|shop|club|live|pro|'
    r'me|tv|cc|us|ca|au|fr|jp|br|in|nl|se|no|fi|dk|pl|be|ch|at|'
    r'es|it|pt|nz|sg|hk|tw|kr|mx|ar|za|ae|il|tr)\b'
)

# extract longest hashes first — SHA256 contains SHA1/MD5 substrings
MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')

# windows paths: C:\Users\something\file.exe
WIN_PATH = re.compile(r'[A-Za-z]:\\(?:[^\\/:\*?"<>|\r\n]+\\)*[^\\/:\*?"<>|\r\n]*')

# unix paths: /var/log/auth.log etc — group capture avoids pulling surrounding quotes
UNIX_PATH = re.compile(r'(?:^|[\s\'"])(/(?:[^/\s\'"]+/)*[^/\s\'"]+)')


# --- Windows Event IDs worth flagging ---
# sourced from SANS Windows log cheat sheet and MITRE ATT&CK
# 4625 = failed logon, 4672 = special privs (watch paired with 4624), etc.

SUSPICIOUS_WIN_EVENTS = {
    "4625": "Failed logon",
    "4648": "Logon with explicit credentials (possible PtH)",
    "4672": "Special privileges assigned to new logon",
    "4698": "Scheduled task created",
    "4720": "New user account created",
    "4728": "User added to global privileged group",
    "4732": "User added to local Administrators",
    "7045": "New service installed on system",
    "1102": "Security audit log cleared",
    "4719": "System audit policy changed",
}


# --- Linux auth/syslog suspicious patterns ---
# each tuple is (compiled regex, label string)
# all patterns checked per line — multiple can match the same entry

SUSPICIOUS_LINUX_PATTERNS = [
    (re.compile(r'Failed password',          re.I), "Failed SSH password"),
    (re.compile(r'authentication failure',   re.I), "PAM auth failure"),
    (re.compile(r'sudo:.+COMMAND',           re.I), "Sudo command ran"),
    (re.compile(r'useradd|adduser',          re.I), "New user added"),
    (re.compile(r'Invalid user',             re.I), "Invalid username attempted"),
    (re.compile(r'ROOT LOGIN',               re.I), "Direct root login"),
    (re.compile(r'session opened for user root', re.I), "Root session opened"),
    (re.compile(r'Accepted publickey',       re.I), "Pubkey auth accepted"),
]
