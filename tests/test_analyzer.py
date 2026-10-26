
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from ssh_log_analyzer import analyze_log


class SSHLogAnalyzerTests(unittest.TestCase):
    def run_analyzer(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.log"
            path.write_text(content)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                analyze_log(path)

            return output.getvalue()

    def test_detects_repeated_failures(self):
        log = "\n".join([
            "2026-10-26T10:00:00 Failed password for user "
            "from 192.0.2.10 port 41001 ssh2",
            "2026-10-26T10:01:00 Failed password for user "
            "from 192.0.2.10 port 41002 ssh2",
            "2026-10-26T10:02:00 Failed password for user "
            "from 192.0.2.10 port 41003 ssh2",
        ])

        result = self.run_analyzer(log)

        self.assertIn("192.0.2.10", result)
        self.assertIn("ALERT", result)

    def test_does_not_alert_for_two_failures(self):
        log = "\n".join([
            "2026-10-26T10:00:00 Failed password for user "
            "from 192.0.2.10 port 41001 ssh2",
            "2026-10-26T10:01:00 Failed password for user "
            "from 192.0.2.10 port 41002 ssh2",
        ])

        result = self.run_analyzer(log)

        self.assertIn("2 failure(s)", result)
        self.assertNotIn(
            "ALERT: 192.0.2.10", result
        )

    def test_detects_successful_login(self):
        log = (
            "2026-10-26T10:00:00 Accepted password for user "
            "from 192.0.2.20 port 42001 ssh2"
        )

        result = self.run_analyzer(log)

        self.assertIn("Successful authentication events: 1", result)


if __name__ == "__main__":
    unittest.main()

