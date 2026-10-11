from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .cli import load_json
from .ct_collector import (
    CertificateTransparencyCollector,
    FixtureCertificateTransparencySource,
)
from .errors import ValidationError
from .models import MonitoringPolicy
from .pipeline import CertificateMonitoringPipeline
from .schema_validation import SchemaRegistry
from .sinks import JsonlAlertSink
from .state import CollectorState


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Process decoded Certificate Transparency fixtures"
    )
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        schemas = SchemaRegistry()
        policy_payload = load_json(args.policy)
        schemas.validate("monitoring-policy", policy_payload)
        policy = MonitoringPolicy.from_dict(policy_payload)
        pipeline = CertificateMonitoringPipeline(policy, schemas)
        source = FixtureCertificateTransparencySource(args.fixture_dir)
        args.state.parent.mkdir(parents=True, exist_ok=True)
        with CollectorState(args.state) as state:
            result = CertificateTransparencyCollector(
                source=source,
                state=state,
                pipeline=pipeline,
                schemas=schemas,
            ).collect()
        sink = JsonlAlertSink(args.output)
        for alert in result.alerts:
            sink.write(alert)
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
        return 0
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
