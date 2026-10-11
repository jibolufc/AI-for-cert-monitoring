from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from .errors import ValidationError


def require_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{path} must be an object")
    return value


def require_exact_keys(
    value: dict[str, Any], required: set[str], optional: set[str], path: str
) -> None:
    missing = required - value.keys()
    extra = value.keys() - required - optional
    if missing:
        raise ValidationError(f"{path} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ValidationError(f"{path} has unexpected keys: {', '.join(sorted(extra))}")


def require_string(
    value: Any, path: str, *, maximum: int = 2048, minimum: int = 1
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        qualifier = "a string" if minimum == 0 else "a non-empty string"
        raise ValidationError(f"{path} must be {qualifier} up to {maximum} characters")
    return value


def require_uuid(value: Any, path: str) -> str:
    text = require_string(value, path, maximum=36)
    try:
        UUID(text)
    except ValueError as exc:
        raise ValidationError(f"{path} must be a UUID") from exc
    return text


def require_timestamp(value: Any, path: str) -> str:
    text = require_string(value, path, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{path} must be an ISO 8601 date-time") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{path} must include a timezone")
    return text


def require_string_list(
    value: Any, path: str, *, minimum: int = 0, maximum: int = 1000
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValidationError(f"{path} must contain between {minimum} and {maximum} items")
    result = [require_string(item, f"{path}[{index}]", maximum=253) for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise ValidationError(f"{path} must not contain duplicate values")
    return result
