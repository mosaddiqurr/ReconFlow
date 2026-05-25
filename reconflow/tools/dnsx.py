"""dnsx integration."""

import json
from pathlib import Path
from typing import Any

from reconflow.core.runner import run_command
from reconflow.models.asset import Asset
from reconflow.tools.base import ToolAdapter
from reconflow.tools.jsonl_utils import load_jsonl_records


def build_dnsx_command(
    input_path: str | Path,
    output_jsonl_path: str | Path,
) -> list[str]:
    """Build a dnsx JSONL output command using a subdomain input file."""
    return [
        "dnsx",
        "-json",
        "-silent",
        "-l",
        str(input_path),
        "-o",
        str(output_jsonl_path),
    ]


def write_dnsx_input(subdomains: list[str], output_path: str | Path) -> Path:
    """Write parsed subdomains to a dnsx-compatible line-delimited input file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(subdomains) + "\n", encoding="utf-8")
    return path


def _coerce_records(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _record_entries(record: dict[str, Any]) -> list[tuple[str | None, str]]:
    entries: list[tuple[str | None, str]] = []

    for record_type in ("a", "aaaa", "cname"):
        for value in _coerce_records(record.get(record_type)):
            entries.append((record_type.upper(), value))

    for response in record.get("resp", []):
        if not isinstance(response, dict):
            continue
        value = response.get("data") or response.get("value")
        if value:
            record_type = response.get("type")
            entries.append(
                (str(record_type).upper() if record_type is not None else None, str(value))
            )

    return entries


def parse_dnsx_jsonl(
    jsonl_path: str | Path,
    parse_warnings: list[str] | None = None,
) -> list[Asset]:
    """Parse dnsx JSONL output into asset models."""
    assets: list[Asset] = []
    for record in load_jsonl_records(jsonl_path, parse_warnings):
        hostname = record.get("host") or record.get("input") or ""
        entries = _record_entries(record)

        if not entries:
            assets.append(
                Asset(
                    hostname=hostname,
                    source_tool="dnsx",
                    is_resolved=False,
                )
            )
            continue

        for record_type, ip in entries:
            assets.append(
                Asset(
                    hostname=hostname,
                    ip=ip,
                    record_type=record_type,
                    source_tool="dnsx",
                    is_resolved=True,
                )
            )

    return assets


def save_assets_json(assets: list[Asset], output_path: str | Path) -> Path:
    """Save parsed DNS assets as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [asset.model_dump() for asset in assets]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def run_dnsx(
    scan_folder: str | Path,
    subdomains: list[str],
    timeout: float | None = None,
):
    """Run dnsx for parsed subdomains using the shared command runner."""
    scan_path = Path(scan_folder)
    input_path = write_dnsx_input(subdomains, scan_path / "raw" / "dnsx_input.txt")
    raw_jsonl_path = scan_path / "raw" / "dnsx.jsonl"
    command = build_dnsx_command(input_path, raw_jsonl_path)
    return run_command("dnsx", command, timeout=timeout)


class DnsxTool(ToolAdapter):
    name = "dnsx"

    def check_available(self) -> bool:
        from shutil import which

        return which("dnsx") is not None

    def build_command(self, target: str) -> list[str]:
        return build_dnsx_command(target, "dnsx.jsonl")
