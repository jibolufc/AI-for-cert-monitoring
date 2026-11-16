"""Regression tests for external code-review findings 1-4."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from crypto_control_plane import ct_cli, roadmap_cli
from crypto_control_plane.models import MonitoringPolicy
from crypto_control_plane.pipeline import CertificateMonitoringPipeline
from crypto_control_plane.schema_validation import SchemaRegistry
from crypto_control_plane.state import CollectorState

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "examples" / "policy.json"
KNOWN_EVENT = ROOT / "examples" / "events" / "known-domain-issued.json"
UNKNOWN_EVENT = ROOT / "examples" / "events" / "unknown-domain-issued.json"
CT_PAGES = ROOT / "examples" / "ct" / "pages"


def _quiet(func, *args):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return func(*args)


class PipelineFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.schemas = SchemaRegistry()
        policy = MonitoringPolicy.from_dict(json.loads(POLICY.read_text(encoding="utf-8")))
        self.pipeline = CertificateMonitoringPipeline(policy, self.schemas)
        self.base_event = json.loads(KNOWN_EVENT.read_text(encoding="utf-8"))

    def event_with(self, *, sans: list[str], subject: str | None = None) -> dict:
        event = copy.deepcopy(self.base_event)
        event["certificate"]["san_dns_names"] = sans
        if subject is not None:
            event["certificate"]["subject"] = subject
        return event


class Finding1WildcardBypass(PipelineFixture):
    def test_wildcard_over_exact_only_name_alerts(self) -> None:
        alert = self.pipeline.process(self.event_with(sans=["*.service.partner-example.org"]))
        self.assertIsNotNone(alert)
        self.assertIn("*.service.partner-example.org", alert["evidence"]["unmatched_dns_names"])

    def test_exact_name_still_allowed(self) -> None:
        self.assertIsNone(self.pipeline.process(self.event_with(sans=["service.partner-example.org"])))

    def test_wildcard_under_approved_suffix_still_allowed(self) -> None:
        self.assertIsNone(self.pipeline.process(self.event_with(sans=["*.example.com"])))


class Finding2AlertsLostOnFailedRun(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.pages = self.work / "pages"
        shutil.copytree(CT_PAGES, self.pages)
        self.state = self.work / "state.sqlite"
        self.alerts = self.work / "alerts.jsonl"

    def run_collector(self) -> int:
        return _quiet(ct_cli.main, ["--fixture-dir", str(self.pages), "--policy", str(POLICY), "--state", str(self.state), "--output", str(self.alerts)])

    def alert_lines(self) -> int:
        if not self.alerts.exists():
            return 0
        return sum(1 for line in self.alerts.read_text(encoding="utf-8").splitlines() if line.strip())

    def test_alert_survives_failure_on_later_page(self) -> None:
        (self.pages / "003-bad.json").write_text(json.dumps({
            "schema_version": "1.1", "log_id": "example-ct-log",
            "page_after_cursor": "2", "next_cursor": "2",
            "collected_at": "2026-10-11T10:02:01Z", "entries": [],
        }), encoding="utf-8")
        self.assertNotEqual(self.run_collector(), 0)
        with CollectorState(self.state) as state:
            self.assertEqual(state.count_observations("alerted"), 1)
        (self.pages / "003-bad.json").unlink()
        self.assertEqual(self.run_collector(), 0)
        self.assertEqual(self.alert_lines(), 1)


class Finding3NoSanNoAlert(PipelineFixture):
    def test_certificate_without_dns_san_alerts(self) -> None:
        self.assertIsNotNone(self.pipeline.process(self.event_with(sans=[], subject="CN=login.evil.net")))


class Finding4SanitisedBundleLeaks(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.work = Path(tempfile.mkdtemp())
        out = cls.work / "release"
        code = _quiet(roadmap_cli.main, ["--event", str(KNOWN_EVENT), "--event", str(UNKNOWN_EVENT), "--output-dir", str(out)])
        if code != 0:
            raise RuntimeError(f"roadmap_cli failed with exit code {code}")
        cls.bundle = json.loads((out / "offline-bundle.json").read_text(encoding="utf-8"))
        cls.artifact_text = json.dumps(cls.bundle["artifacts"], sort_keys=True)
        cls.known_event = json.loads(KNOWN_EVENT.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_bundle_claims_sanitised(self) -> None:
        self.assertTrue(self.bundle["manifest"]["sanitised"])

    def test_raw_asset_id_not_present(self) -> None:
        self.assertNotIn(self.known_event["context"]["asset_id"], self.artifact_text)

    def test_deterministic_event_id_not_present(self) -> None:
        self.assertNotIn(self.known_event["event_id"], self.artifact_text)

    def test_dns_san_names_not_present(self) -> None:
        for name in self.known_event["certificate"]["san_dns_names"]:
            self.assertNotIn(name, self.artifact_text)

    def test_redaction_token_not_reversible_by_guessing(self) -> None:
        subject = self.known_event["certificate"]["subject"]
        guessed = "redacted:" + hashlib.sha256(subject.encode()).hexdigest()[:12]
        tokens = {record["certificate"]["subject"] for record in self.bundle["artifacts"]["inventory"]}
        self.assertNotIn(guessed, tokens)


if __name__ == "__main__":
    unittest.main()
