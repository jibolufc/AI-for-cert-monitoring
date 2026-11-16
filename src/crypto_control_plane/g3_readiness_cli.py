from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .cli import load_json
from .errors import ValidationError
from .g3_readiness import G3ReadinessGate
from .schema_validation import SchemaRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Assess Gate G3 readiness without granting collection authority")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--as-of", required=True, help="Timezone-aware ISO 8601 assessment time")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = G3ReadinessGate(SchemaRegistry()).assess(load_json(args.plan), as_of=args.as_of)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] != "blocked" else 3
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
