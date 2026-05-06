from __future__ import annotations

import json
import re
from typing import Iterable

FLAG_RE = re.compile(r"THM\{[^}]+\}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def extract_flags(text: str) -> list[str]:
    return FLAG_RE.findall(text or "")


def extract_first_flag(text: str) -> str | None:
    hits = extract_flags(text)
    return hits[0] if hits else None


def extract_emails(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for email in EMAIL_RE.findall(text or ""):
        if email not in seen:
            seen[email] = None
    return list(seen.keys())


def merge_unique(items: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        if item and item not in seen:
            seen[item] = None
    return list(seen.keys())


def try_parse_json(text: str) -> dict | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None
