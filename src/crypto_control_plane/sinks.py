from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonlAlertSink:
    """Local development sink; not a production integrity boundary."""

    def __init__(self, path: Path):
        self.path = path

    def write(self, alert: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
