# tests/test_parsers.py
#
# integration tests for parse_auth, parse_syslog
# these run against the actual sample files in tests/samples/
# so they test the full parsing pipeline, not just individual functions
#
# run with: python -m pytest tests/test_parsers.py -v
# Isaiah

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from parsers import parse_auth, parse_syslog

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
SAMPLE_AUTH   = os.path.join(SAMPLES_DIR, "sample_auth.log")
SAMPLE_SYSLOG = os.path.join(SAMPLES_DIR, "sample_syslog.log")


class TestAuthParser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # parse once, reuse across all test methods
        cls.entries = parse_auth(SAMPLE_AUTH)

    def test_returns_list(self):
        self.assertIsInstance(self.entries, list)

    def test_entry_count_reasonable(self):
        # sample_auth.log has ~22 lines (including comment lines which become raw entries)
        self.assertGreater(len(self.entries), 10)

    def test_all_entries_have_required_keys(self):
        required = {"timestamp", "source_ip", "destination_ip", "user",
                    "event_id", "action", "raw", "iocs", "flags"}
        for entry in self.entries:
            self.assertTrue(required.issubset(entry.keys()),
                            f"entry missing keys: {required - entry.keys()}")

    def test_failed_password_entries_flagged(self):
        flagged = [e for e in self.entries if e.get("flags")]
        self.assertGreater(len(flagged), 0, "expected some flagged entries")

    def test_source_ip_extracted_from_ssh_line(self):
        # 198.51.100.42 appears in multiple failed password lines
        ips_found = [e["source_ip"] for e in self.entries if e.get("source_ip")]
        self.assertIn("198.51.100.42", ips_found)

    def test_attacker_ip_present(self):
        # 185.220.101.5 is the brute force IP in the sample
        ips_found = [e["source_ip"] for e in self.entries if e.get("source_ip")]
        self.assertIn("185.220.101.5", ips_found)

    def test_root_login_flagged(self):
        root_flags = [
            e for e in self.entries
            if any("root" in f.lower() for f in e.get("flags", []))
        ]
        self.assertGreater(len(root_flags), 0, "expected root login to be flagged")

    def test_sudo_entry_flagged(self):
        sudo_flags = [
            e for e in self.entries
            if any("sudo" in f.lower() or "Sudo" in f for f in e.get("flags", []))
        ]
        self.assertGreater(len(sudo_flags), 0, "expected sudo command to be flagged")

    def test_user_field_extracted(self):
        users = [e["user"] for e in self.entries if e.get("user")]
        self.assertTrue(len(users) > 0, "should have extracted at least one username")
        # root and deploy both appear in the sample
        self.assertTrue(any(u in ["root", "deploy", "admin"] for u in users))

    def test_timestamps_are_iso_format(self):
        # all parsed timestamps should be ISO format (or None for unparseable lines)
        for entry in self.entries:
            ts = entry.get("timestamp")
            if ts and ts != "None":
                # basic check: should contain T separator between date and time
                self.assertIn("T", ts, f"timestamp not ISO format: {ts}")

    def test_iocs_dict_type(self):
        for entry in self.entries:
            self.assertIsInstance(entry["iocs"], dict)

    def test_flags_list_type(self):
        for entry in self.entries:
            self.assertIsInstance(entry["flags"], list)

    def test_sha1_hash_extracted_from_kernel_line(self):
        # sample has a SHA1 hash on the rootkit.ko line
        all_iocs = {}
        for entry in self.entries:
            for k, v in entry.get("iocs", {}).items():
                all_iocs.setdefault(k, []).extend(v)
        self.assertIn("sha1", all_iocs, "should have found the SHA1 hash in kernel line")

    def test_raw_field_is_never_empty_for_valid_lines(self):
        # every entry should have the original line in raw
        # (comment lines in the sample start with # so they'll have something)
        for entry in self.entries:
            self.assertIsNotNone(entry.get("raw"))


class TestSyslogParser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.entries = parse_syslog(SAMPLE_SYSLOG)

    def test_returns_list(self):
        self.assertIsInstance(self.entries, list)

    def test_entry_count_reasonable(self):
        self.assertGreater(len(self.entries), 10)

    def test_all_entries_have_required_keys(self):
        required = {"timestamp", "source_ip", "destination_ip", "user",
                    "event_id", "action", "raw", "iocs", "flags"}
        for entry in self.entries:
            self.assertTrue(required.issubset(entry.keys()))

    def test_brute_force_ip_extracted(self):
        # 45.33.32.156 is the scanning IP in sample_syslog.log
        ips = [e["source_ip"] for e in self.entries if e.get("source_ip")]
        self.assertIn("45.33.32.156", ips)

    def test_failed_logins_flagged(self):
        flagged = [e for e in self.entries if e.get("flags")]
        self.assertGreater(len(flagged), 0)

    def test_md5_hash_extracted(self):
        # sample_syslog has "d8e8fca2dc0f896fd7cb4cb0031ba249" on the sudo mismatch line
        all_md5 = []
        for entry in self.entries:
            all_md5.extend(entry.get("iocs", {}).get("md5", []))
        self.assertIn("d8e8fca2dc0f896fd7cb4cb0031ba249", all_md5)

    def test_sha1_hash_extracted(self):
        all_sha1 = []
        for entry in self.entries:
            all_sha1.extend(entry.get("iocs", {}).get("sha1", []))
        self.assertIn("da39a3ee5e6b4b0d3255bfef95601890afd80709", all_sha1)

    def test_domain_extracted(self):
        all_domains = []
        for entry in self.entries:
            all_domains.extend(entry.get("iocs", {}).get("domain", []))
        self.assertTrue(
            any("shodan" in d or "example" in d for d in all_domains),
            "expected a domain from the sample syslog"
        )

    def test_action_field_is_process_name(self):
        # in syslog the action field gets set to the process name
        actions = [e["action"] for e in self.entries if e.get("action")]
        self.assertTrue(len(actions) > 0)
        # should have things like sshd, CRON, systemd
        proc_names = [a.strip() for a in actions]
        self.assertTrue(any(p in proc_names for p in ["sshd", "CRON", "systemd", "sudo"]))


class TestParserEdgeCases(unittest.TestCase):
    """tests for edge cases and things that broke during dev"""

    def test_parse_auth_empty_lines_handled(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("\n\n\n")
            path = f.name
        try:
            result = parse_auth(path)
            # empty lines should be skipped, not cause a crash or empty-entry explosion
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(path)

    def test_parse_syslog_malformed_lines_dont_crash(self):
        import tempfile
        weird_content = (
            "this line has no timestamp or hostname\n"
            "Jan 15 03:22:11 host proc[123]: normal line after bad one\n"
            ":::::::::::\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(weird_content)
            path = f.name
        try:
            result = parse_syslog(path)
            self.assertIsInstance(result, list)
            # should have gotten the 2 non-empty lines at minimum
            self.assertGreater(len(result), 0)
        finally:
            os.unlink(path)

    def test_parse_auth_single_valid_line(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("Jan 15 03:22:11 server sshd[1842]: Failed password for root from 1.2.3.4 port 22 ssh2\n")
            path = f.name
        try:
            result = parse_auth(path)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["source_ip"], "1.2.3.4")
            self.assertIn("Failed SSH password", result[0]["flags"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
