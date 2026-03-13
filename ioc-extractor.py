# ioc_extractor.py
# pulls IOCs out of a raw string and returns them as a dict
# used by both the parsers and can be called standalone if needed
#
# the merge_iocs function handles combining per-entry iocs into a global set
# Isaiah

import re
from patterns import IPV4, IPV6, DOMAIN, MD5, SHA1, SHA256, WIN_PATH, UNIX_PATH

# IPs that aren't worth flagging - loopback, unroutable, broadcast
# might expand this later (APIPA range etc)
BORING_IPS = ("127.", "0.0.0", "255.255", "169.254")


def extract_iocs(text):
    """
    takes a raw string (log line, xml blob, whatever) and pulls out
    any IOCs it can find. returns a dict, empty if nothing found.

    handles hashes carefully - SHA256 gets pulled first, then we scrub
    those chars before looking for SHA1, then MD5. otherwise a SHA256
    hash will also match SHA1 and MD5 patterns (it contains them).
    """
    found = {}

    # IPs
    v4_hits = [ip for ip in IPV4.findall(text) if not ip.startswith(BORING_IPS)]
    if v4_hits:
        # dedupe but keep order - dict.fromkeys trick
        found["ipv4"] = list(dict.fromkeys(v4_hits))

    v6_hits = IPV6.findall(text)
    if v6_hits:
        found["ipv6"] = list(dict.fromkeys(v6_hits))

    # domains
    domains = DOMAIN.findall(text)
    if domains:
        found["domain"] = list(dict.fromkeys(domains))

    # hashes - do the scrubbing thing so longer hashes dont pollute shorter matches
    sha256_hits = SHA256.findall(text)
    working = text
    for h in sha256_hits:
        working = working.replace(h, "")  # remove from working copy

    sha1_hits = SHA1.findall(working)
    for h in sha1_hits:
        working = working.replace(h, "")

    md5_hits = MD5.findall(working)

    if sha256_hits:
        found["sha256"] = list(dict.fromkeys(sha256_hits))
    if sha1_hits:
        found["sha1"] = list(dict.fromkeys(sha1_hits))
    if md5_hits:
        found["md5"] = list(dict.fromkeys(md5_hits))

    # file paths - combine windows and unix results
    win = WIN_PATH.findall(text)
    unix = UNIX_PATH.findall(text)
    paths = list(dict.fromkeys(win + unix))
    if paths:
        found["filepath"] = paths

    return found


def merge_iocs(global_iocs, new_iocs):
    """
    merges new_iocs into global_iocs (in place, using sets for deduplication)
    called once per log entry as we loop through the file
    """
    for ioc_type, values in new_iocs.items():
        if ioc_type not in global_iocs:
            global_iocs[ioc_type] = set()
        global_iocs[ioc_type].update(values)


def finalize_iocs(global_iocs):
    """
    converts the sets to sorted lists so we can dump to JSON
    also just cleaner to look at in the output
    """
    return {k: sorted(list(v)) for k, v in global_iocs.items()}
