# patterns.py
# all the regex stuff and suspicious event ID lists live here
# keeping it separate so i dont have to scroll through main to change a pattern
# Isaiah - started this for my CIT 499 project, kept building it out

import re

# --- IOC patterns ---
# learned about the hash length trick from a SO post - SHA256 is 64 chars,
# SHA1 is 40, MD5 is 32. gotta strip longer ones first or you get false matches

IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# ipv6 is kinda ugly but it works for full and compressed addresses
IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}'
)

# domain regex - only matches common TLDs so we dont pull garbage
# not exhaustive but covers most of what shows up in logs
DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|edu|gov|mil|io|co|uk|de|ru|cn|info|biz|xyz|'
    r'top|site|online|tech|app|dev|cloud|store|shop|club|live|pro|'
    r'me|tv|cc|us|ca|au|fr|jp|br|in|nl|se|no|fi|dk|pl|be|ch|at|'
    r'es|it|pt|nz|sg|hk|tw|kr|mx|ar|za|ae|il|tr)\b'
)

MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')

# windows paths like C:\Users\something
WIN_PATH = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')

# unix paths - the group capture avoids pulling the quote or space before the slash
UNIX_PATH = re.compile(r'(?:^|[\s\'"])(/(?:[^/\s\'"]+/)*[^/\s\'"]+)')


# --- Windows Event IDs worth flagging ---
# pulled these from the SANS Windows log cheat sheet and my Security+ notes
# 4625 = failed logon, 4672 = special privs (watch for this with 4624), etc.
SUSPICIOUS_WIN_EVENTS = {
    "4625": "Failed logon",
    "4648": "Logon with explicit credentials (could be PtH)",
    "4672": "Special privileges assigned to new logon",
    "4698": "Scheduled task created",
    "4720": "New user account created",
    "4728": "User added to global privileged group",
    "4732": "User added to local Administrators",
    "7045": "New service installed on system",
    "1102": "Security audit log was cleared",  # big red flag
    "4719": "System audit policy changed",
}

# --- Auth/syslog suspicious patterns ---
# regex + a label for what it means in the output
# order doesnt really matter here since we check all of them per line
SUSPICIOUS_LINUX_PATTERNS = [
    (re.compile(r'Failed password', re.I),              "Failed SSH password"),
    (re.compile(r'authentication failure', re.I),       "PAM auth failure"),
    (re.compile(r'sudo:.+COMMAND', re.I),               "Sudo command ran"),
    (re.compile(r'useradd|adduser', re.I),              "New user added"),
    (re.compile(r'Invalid user', re.I),                 "Invalid username attempted"),
    (re.compile(r'ROOT LOGIN', re.I),                   "Direct root login"),
    (re.compile(r'session opened for user root', re.I), "Root session opened"),
    (re.compile(r'Accepted publickey', re.I),           "Pubkey auth accepted"),
]
