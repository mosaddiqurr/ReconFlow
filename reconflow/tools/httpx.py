"""httpx integration."""

import json
from pathlib import Path
from typing import Any

from reconflow.core.runner import run_command
from reconflow.models.live_host import LiveHost

from reconflow.tools.base import ToolAdapter


def select_httpx_inputs(target: str, resolved_hosts: list[str] | None = None) -> list[str]:
    """Prefer resolved hosts when present, otherwise probe the original target."""
    if resolved_hosts:
        return resolved_hosts
    return [target]


def build_httpx_command(
    inputs: list[str],
    output_jsonl_path: str | Path,
    input_file_path: str | Path | None = None,
) -> list[str]:
    """Build an httpx JSONL output command."""
    base_command = ["httpx", "-json", "-silent", "-o", str(output_jsonl_path)]
    if len(inputs) == 1:
        return [*base_command, "-u", inputs[0]]

    if input_file_path is None:
        raise ValueError("input_file_path is required when probing multiple inputs")

    return [*base_command, "-l", str(input_file_path)]


def _coerce_technologies(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _coerce_content_length(record: dict[str, Any]) -> int | None:
    value = record.get("content_length", record.get("content-length"))
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_httpx_jsonl(jsonl_path: str | Path) -> list[LiveHost]:
    """Parse httpx JSONL output into live host models."""
    live_hosts: list[LiveHost] = []
    for line in Path(jsonl_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue

        record = json.loads(line)
        url = record.get("url", "")
        live_hosts.append(
            LiveHost(
                url=url,
                host=record.get("host") or record.get("input") or url,
                status_code=record.get("status_code"),
                title=record.get("title", ""),
                webserver=record.get("webserver") or record.get("server", ""),
                content_length=_coerce_content_length(record),
                technologies=_coerce_technologies(
                    record.get("technologies", record.get("tech"))
                ),
                source_tool="httpx",
            )
        )

    return live_hosts


def save_live_hosts_json(live_hosts: list[LiveHost], output_path: str | Path) -> Path:
    """Save parsed live hosts as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [live_host.model_dump() for live_host in live_hosts]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def run_httpx(
    target: str,
    scan_folder: str | Path,
    resolved_hosts: list[str] | None = None,
    timeout: float | None = None,
):
    """Run httpx through the shared command runner."""
    scan_path = Path(scan_folder)
    raw_jsonl_path = scan_path / "raw" / "httpx.jsonl"
    inputs = select_httpx_inputs(target, resolved_hosts)
    input_file_path = None
    if len(inputs) > 1:
        input_file_path = scan_path / "raw" / "httpx_inputs.txt"
        input_file_path.write_text("\n".join(inputs) + "\n", encoding="utf-8")

    command = build_httpx_command(inputs, raw_jsonl_path, input_file_path)
    return run_command("httpx", command, timeout=timeout)


class HttpxTool(ToolAdapter):
    name = "httpx"

    def check_available(self) -> bool:
        from shutil import which

        return which("httpx") is not None

    def build_command(self, target: str) -> list[str]:
        return build_httpx_command([target], "httpx.jsonl")
