from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import ValidationError


class JsonlAlertSink:
    """Local development sink; not a production integrity boundary."""

    def __init__(self, path: Path):
        self.path = path

    def write(self, alert: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        alert_id = alert["alert_id"]
        encoded = json.dumps(alert, sort_keys=True, separators=(",", ":"))
        existing = ""
        if self.path.exists():
            existing = self.path.read_text(encoding="utf-8")
            try:
                records = [json.loads(line) for line in existing.splitlines() if line.strip()]
            except json.JSONDecodeError as exc:
                raise ValidationError(f"alert sink contains invalid JSONL: {self.path}") from exc
            for record in records:
                if record.get("alert_id") == alert_id:
                    if json.dumps(record, sort_keys=True, separators=(",", ":")) != encoded:
                        raise ValidationError(
                            f"alert sink id collision with different payload: {alert_id}"
                        )
                    return
        content = existing
        if content and not content.endswith("\n"):
            content += "\n"
        content += encoded + "\n"
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()
