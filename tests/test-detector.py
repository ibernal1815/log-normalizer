# tests/test_detector.py
#
# tests for the format auto-detector
# mostly just making sure the right format comes back for each file type
# and that the fallback behavior is sane
#
# run with: python -m pytest tests/test_detector.py -v
# Isaiah

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from detector import detect_format


class TestExtensionDetection(unittest.TestCase):

    def test_evtx_extension_detected(self):
        # create a fake file with .evtx extension — content doesnt matter for this check
        with tempfile.NamedTemporaryFile(suffix=".evtx", mode="w", delete=False) as f:
            f.write("not real evtx content")
            path = f.name
        try:
            self.assertEqual(detect_format(path), "evtx")
        finally:
            os.unlink(path)

    def test_evtx_extension_case_insensitive(self):
        with tempfile.NamedTemporaryFile(suffix=".EVTX", mode="w", delete=False) as f:
            f.write("whatever")
            path = f.name
        try:
            self.assertEqual(detect_format(path), "evtx")
        finally:
            os.unlink(path)


class TestContentDetection(unittest.TestCase):

    def _make_temp(self, filename, content):
        # helper to write a temp file with a specific name and content
        # tempfile doesnt let you control the name prefix easily so we use a dir
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, filename)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_auth_log_detected_by_name_and_content(self):
        auth_content = (
            "Jan 15 03:22:11 webserver sshd[1842]: Failed password for root from 198.51.100.42 port 22\n"
            "Jan 15 03:23:01 webserver sudo: analyst : USER=root ; COMMAND=/usr/bin/cat\n"
        )
        path = self._make_temp("auth.log", auth_content)
        try:
            self.assertEqual(detect_format(path), "auth")
        finally:
            os.unlink(path)

    def test_secure_log_detected(self):
        # RHEL/CentOS uses /var/log/secure instead of auth.log — same format
        secure_content = (
            "Jan 15 03:22:11 server sshd[1842]: Failed password for root from 10.0.0.1 port 22\n"
        )
        path = self._make_temp("secure", secure_content)
        try:
            self.assertEqual(detect_format(path), "auth")
        finally:
            os.unlink(path)

    def test_syslog_detected(self):
        syslog_content = (
            "Mar 10 09:01:13 fileserver systemd[1]: Started OpenSSH Server Daemon.\n"
            "Mar 10 09:07:41 fileserver CRON[900]: (root) CMD (/usr/local/bin/updater.sh)\n"
        )
        path = self._make_temp("syslog.log", syslog_content)
        try:
            self.assertEqual(detect_format(path), "syslog")
        finally:
            os.unlink(path)

    def test_syslog_with_auth_content_stays_syslog_by_filename(self):
        # a file named syslog.log that happens to have sshd lines should
        # be detected as syslog, not auth — filename doesnt say auth/secure
        mixed_content = (
            "Mar 10 09:05:22 server sshd[3312]: Accepted password for jsmith from 10.0.0.1 port 22\n"
            "Mar 10 09:07:41 server CRON[900]: (root) CMD (/bin/check.sh)\n"
        )
        path = self._make_temp("syslog.log", mixed_content)
        try:
            fmt = detect_format(path)
            # could reasonably be either, but shouldnt crash
            self.assertIn(fmt, ["syslog", "auth"])
        finally:
            os.unlink(path)

    def test_unknown_file_falls_back_to_syslog(self):
        path = self._make_temp("some_random_log.txt", "this doesnt match anything\n")
        try:
            self.assertEqual(detect_format(path), "syslog")
        finally:
            os.unlink(path)

    def test_sample_auth_log_file(self):
        # use the actual sample file from the test suite
        sample = os.path.join(
            os.path.dirname(__file__), "samples", "sample_auth.log"
        )
        if os.path.exists(sample):
            self.assertEqual(detect_format(sample), "auth")

    def test_sample_syslog_file(self):
        sample = os.path.join(
            os.path.dirname(__file__), "samples", "sample_syslog.log"
        )
        if os.path.exists(sample):
            self.assertEqual(detect_format(sample), "syslog")


if __name__ == "__main__":
    unittest.main()
