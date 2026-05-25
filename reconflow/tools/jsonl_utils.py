"""Shared JSONL parsing helpers for tool output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_jsonl_records(
    jsonl_path: str | Path,
    parse_warnings: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Load valid JSON object records from JSONL, skipping malformed lines."""
    records: list[dict[str, Any]] = []
    malformed_line_count = 0
    non_object_count = 0

    for line in Path(jsonl_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            malformed_line_count += 1
            continue

        if not isinstance(record, dict):
            non_object_count += 1
            continue

        records.append(record)

    if parse_warnings is not None:
        if malformed_line_count:
            parse_warnings.append(
                _count_message(malformed_line_count, "malformed JSONL line")
            )
        if non_object_count:
            parse_warnings.append(
                _count_message(non_object_count, "non-object JSONL record")
            )

    return records


def _count_message(count: int, singular: str) -> str:
    suffix = singular if count == 1 else f"{singular}s"
    return f"Skipped {count} {suffix}"
