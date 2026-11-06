"""Look through what a tool returned. The log records rule ids and counts, never values."""

import json
import os
import re
import time

from .config import state_dir
from .mask import mask_text

MAX_TEXT = 4 * 1024 * 1024  # longer strings (images, archives) are left alone
_MARKER = re.compile(r"\[hushhook:[a-z0-9-]+\]")


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def find(value, rules):
    """Count secret hits in any JSON-like value. Returns {rule_id: count}."""
    counts = {}
    for text in _strings(value):
        if len(text) > MAX_TEXT:
            continue
        text = _MARKER.sub("", text)
        lowered = text.lower()
        for rule in rules:
            if not rule.worth_trying(text, lowered):
                continue
            hits = sum(1 for _ in rule.regex.finditer(text))
            if hits:
                counts[rule.id] = counts.get(rule.id, 0) + hits
    return counts


def mask_value(value, rules):
    """Return a copy with the same shape and every string masked."""
    if isinstance(value, str):
        return mask_text(value, rules) if len(value) <= MAX_TEXT else value
    if isinstance(value, dict):
        return {key: mask_value(item, rules) for key, item in value.items()}
    if isinstance(value, list):
        return [mask_value(item, rules) for item in value]
    return value


def leaks_path():
    return os.path.join(state_dir(), "leaks.jsonl")


def record(tool, counts, path=None):
    """Append one line per rule: time, tool, rule id and count. Readable by the owner only."""
    path = path or leaks_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    lines = "".join(
        json.dumps({"time": stamp, "tool": str(tool)[:64], "rule": rule_id, "count": count}) + "\n"
        for rule_id, count in sorted(counts.items())
    )
    handle = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(handle, "a", encoding="utf-8") as stream:
        stream.write(lines)
