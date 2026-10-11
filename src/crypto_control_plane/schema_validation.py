from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError as JsonSchemaValidationError

from .errors import ValidationError


SCHEMA_FILES = {
    "certificate-event": "certificate-event.schema.json",
    "detection-alert": "detection-alert.schema.json",
    "monitoring-policy": "monitoring-policy.schema.json",
    "ct-observation-page": "ct-observation-page.schema.json",
}


class SchemaRegistry:
    """Loads and applies the repository's versioned JSON Schema contracts."""

    def __init__(self, schema_directory: Path | None = None):
        self.schema_directory = schema_directory or self.default_schema_directory()
        self._validators: dict[str, Draft202012Validator] = {}

    @staticmethod
    def default_schema_directory() -> Path:
        return Path(__file__).resolve().parents[2] / "schemas"

    def validate(self, contract: str, payload: Any) -> None:
        validator = self._validators.get(contract)
        if validator is None:
            validator = self._load(contract)
            self._validators[contract] = validator
        try:
            validator.validate(payload)
        except JsonSchemaValidationError as exc:
            location = ".".join(str(part) for part in exc.absolute_path)
            prefix = f"{contract}.{location}" if location else contract
            raise ValidationError(f"{prefix}: {exc.message}") from exc

    def _load(self, contract: str) -> Draft202012Validator:
        try:
            filename = SCHEMA_FILES[contract]
        except KeyError as exc:
            raise ValidationError(f"unknown schema contract: {contract}") from exc
        path = self.schema_directory / filename
        try:
            import json

            schema = json.loads(path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
        except (OSError, ValueError, SchemaError) as exc:
            raise ValidationError(f"cannot load valid schema {path}: {exc}") from exc
        return Draft202012Validator(schema, format_checker=FormatChecker())
