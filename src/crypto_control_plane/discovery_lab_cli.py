from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys
from pathlib import Path

from .cli import load_json
from .discovery_lab import X509CertificateDiscovery
from .errors import ValidationError
from .inventory import PqcInventoryService
from .models import CertificateEvent
from .schema_validation import SchemaRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse one generated or sanitised X.509 certificate into PQC discovery evidence"
    )
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument(
        "--evidence-level",
        choices=("generated", "sanitised-capture"),
        required=True,
    )
    parser.add_argument("--context", type=Path)
    parser.add_argument("--observed-at")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        schemas = SchemaRegistry()
        context = None if args.context is None else load_json(args.context)
        observed_at = args.observed_at or datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        event = X509CertificateDiscovery(schemas).parse_file(
            args.certificate,
            evidence_level=args.evidence_level,
            observed_at=observed_at,
            context=context,
        )
        assessed = PqcInventoryService(schemas).assess_certificate_event(
            CertificateEvent.from_dict(event)
        )
        output = {
            "event": event,
            "record": assessed.record,
            "assessment": assessed.assessment,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
