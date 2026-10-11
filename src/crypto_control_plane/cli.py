from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import ValidationError
from .models import MonitoringPolicy
from .pipeline import CertificateMonitoringPipeline
from .sinks import JsonlAlertSink


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process one canonical certificate event")
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = MonitoringPolicy.from_dict(load_json(args.policy))
        alert = CertificateMonitoringPipeline(policy).process(load_json(args.event))
        if alert is None:
            print("no alert")
            return 0
        JsonlAlertSink(args.output).write(alert)
        print(json.dumps(alert, indent=2, sort_keys=True))
        return 0
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
