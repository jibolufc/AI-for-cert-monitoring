from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .cli import load_json
from .errors import ValidationError
from .inventory import PqcInventoryService
from .models import CertificateEvent
from .schema_validation import SchemaRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build one evidence-backed cryptographic inventory assessment"
    )
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = load_json(args.event)
        schemas = SchemaRegistry()
        schemas.validate("certificate-event", payload)
        result = PqcInventoryService(schemas).assess_certificate_event(
            CertificateEvent.from_dict(payload)
        )
        output = {"record": result.record, "assessment": result.assessment}
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
