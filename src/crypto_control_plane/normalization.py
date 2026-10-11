from __future__ import annotations

from .errors import ValidationError


def normalize_dns_name(value: str, *, allow_wildcard: bool = True) -> str:
    candidate = value.strip().rstrip(".").lower()
    wildcard = candidate.startswith("*.")
    if "*" in candidate and not wildcard:
        raise ValidationError(f"invalid wildcard DNS name: {value!r}")
    if wildcard:
        if not allow_wildcard:
            raise ValidationError(f"wildcards are not allowed in policy values: {value!r}")
        candidate = candidate[2:]
    if not candidate or len(candidate) > 253:
        raise ValidationError(f"invalid DNS name length: {value!r}")
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError(f"invalid internationalized DNS name: {value!r}") from exc
    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise ValidationError(f"DNS name must contain at least two labels: {value!r}")
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValidationError(f"invalid DNS label in {value!r}")
        if any(not (ch.isalnum() or ch == "-") for ch in label):
            raise ValidationError(f"invalid character in DNS name: {value!r}")
    return f"*.{ascii_name}" if wildcard else ascii_name


def policy_candidate(name: str) -> str:
    return name[2:] if name.startswith("*.") else name


def matches_policy(name: str, exact_names: tuple[str, ...], suffixes: tuple[str, ...]) -> bool:
    candidate = policy_candidate(name)
    if candidate in exact_names:
        return True
    return any(candidate == suffix or candidate.endswith(f".{suffix}") for suffix in suffixes)
