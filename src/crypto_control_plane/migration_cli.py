from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .cli import load_json
from .errors import ValidationError
from .migration import MigrationPlanner
from .schema_validation import SchemaRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a deterministic PQC migration plan from an enterprise catalogue"
    )
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        catalog = load_json(args.catalog)
        result = MigrationPlanner(SchemaRegistry()).plan(catalog)
        output = {
            "catalog": catalog,
            "work_items": list(result.work_items),
            "coverage_report": result.coverage_report,
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
