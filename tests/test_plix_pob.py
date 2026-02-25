import os
import tempfile
import unittest

from honeypot.plix_pob import PLIXPOBEngine, HoneypotEvent, heuristic_classification


class TestPLIXPOB(unittest.TestCase):
    def test_heuristic_detects_high_risk(self):
        event = HoneypotEvent(
            timestamp="2026-01-01T00:00:00+00:00",
            source_ip="10.0.0.2",
            method="POST",
            path="/wp-login.php",
            user_agent="sqlmap/1.7",
            query="",
        )
        severity, reason = heuristic_classification(event)
        self.assertEqual(severity, "high")
        self.assertIn("Heuristic", reason)

    def test_heuristic_detects_low_risk(self):
        event = HoneypotEvent(
            timestamp="2026-01-01T00:00:00+00:00",
            source_ip="10.0.0.2",
            method="GET",
            path="/favicon.ico",
            user_agent="Mozilla/5.0",
            query="",
        )
        severity, _ = heuristic_classification(event)
        self.assertEqual(severity, "low")

    def test_engine_writes_log_and_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "events.jsonl")
            engine = PLIXPOBEngine(log_file=log_path)
            result = engine.process(
                source_ip="127.0.0.1",
                method="GET",
                path="/admin",
                user_agent="Mozilla/5.0",
            )
            self.assertIn("plix_pob", result)
            self.assertTrue(os.path.exists(log_path))
            self.assertGreater(os.path.getsize(log_path), 0)


if __name__ == "__main__":
    unittest.main()
