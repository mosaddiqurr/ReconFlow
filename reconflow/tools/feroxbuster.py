"""Feroxbuster integration."""

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reconflow.core.runner import run_command
from reconflow.models.endpoint import Endpoint
from reconflow.tools.base import ToolAdapter
from reconflow.tools.jsonl_utils import load_jsonl_records


INTERESTING_PATH_MARKERS = (
    "admin",
    "login",
    "backup",
    "config",
    "upload",
    "dashboard",
    "wp-admin",
    "api",
)


def load_feroxbuster_targets(live_hosts_path: str | Path) -> list[str]:
    """Load Feroxbuster target URLs from parsed httpx live hosts."""
    live_hosts = json.loads(Path(live_hosts_path).read_text(encoding="utf-8"))
    targets: list[str] = []
    seen: set[str] = set()

    for live_host in live_hosts:
        url = str(live_host.get("url", "")).strip()
        if not url or url in seen:
            continue
        seen.add(url)
        targets.append(url)

    return targets


def build_feroxbuster_command(
    targets: list[str],
    output_json_path: str | Path,
    wordlist_path: str | Path,
) -> list[str]:
    """Build a conservative Feroxbuster command for authorized testing."""
    if not targets:
        raise ValueError("targets are required to build a Feroxbuster command")

    command = [
        "feroxbuster",
        "--json",
        "--silent",
        "--depth",
        "1",
        "--threads",
        "5",
        "--rate-limit",
        "25",
        "--timeout",
        "5",
        "--wordlist",
        str(wordlist_path),
        "-o",
        str(output_json_path),
    ]
    for target in targets:
        command.extend(["--url", target])

    return command


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_interesting_path(path: str) -> bool:
    """Return whether a path matches ReconFlow's interesting endpoint markers."""
    normalized_path = path.lower()
    return any(marker in normalized_path for marker in INTERESTING_PATH_MARKERS)


def _endpoint_from_record(record: dict[str, Any]) -> Endpoint:
    url = str(record.get("url", ""))
    parsed_url = urlparse(url)
    path = parsed_url.path or "/"
    return Endpoint(
        url=url,
        host=parsed_url.netloc or str(record.get("host", "")),
        path=path,
        status_code=_coerce_int(record.get("status", record.get("status_code"))),
        content_length=_coerce_int(
            record.get("content_length", record.get("content-length"))
        ),
        words=_coerce_int(record.get("words")),
        lines=_coerce_int(record.get("lines")),
        source_tool="feroxbuster",
        interesting=is_interesting_path(path),
    )


def _load_feroxbuster_records(
    output_path: str | Path,
    parse_warnings: list[str] | None = None,
) -> list[dict[str, Any]]:
    text = Path(output_path).read_text(encoding="utf-8").strip()
    if not text:
        return []

    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return load_jsonl_records(output_path, parse_warnings)

    if isinstance(loaded, list):
        return [record for record in loaded if isinstance(record, dict)]
    if isinstance(loaded, dict):
        results = loaded.get("results")
        if isinstance(results, list):
            return [record for record in results if isinstance(record, dict)]
        return [loaded]
    return []


def parse_feroxbuster_json(
    output_path: str | Path,
    parse_warnings: list[str] | None = None,
) -> list[Endpoint]:
    """Parse Feroxbuster JSON output into endpoint models."""
    endpoints: list[Endpoint] = []
    for record in _load_feroxbuster_records(output_path, parse_warnings):
        if record.get("type") and record.get("type") != "response":
            continue
        if not record.get("url"):
            continue
        endpoints.append(_endpoint_from_record(record))

    return endpoints


def save_endpoints_json(endpoints: list[Endpoint], output_path: str | Path) -> Path:
    """Save parsed endpoint models as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [endpoint.model_dump() for endpoint in endpoints]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def run_feroxbuster(
    scan_folder: str | Path,
    live_hosts_path: str | Path,
    wordlist_path: str | Path,
    timeout: float | None = None,
):
    """Run Feroxbuster against URLs from parsed live hosts."""
    scan_path = Path(scan_folder)
    raw_json_path = scan_path / "raw" / "feroxbuster.json"
    targets = load_feroxbuster_targets(live_hosts_path)
    command = build_feroxbuster_command(targets, raw_json_path, wordlist_path)
    return run_command("feroxbuster", command, timeout=timeout)


class FeroxbusterTool(ToolAdapter):
    name = "feroxbuster"

    def check_available(self) -> bool:
        from shutil import which

        return which("feroxbuster") is not None

    def build_command(self, target: str) -> list[str]:
        return build_feroxbuster_command(
            [target],
            "feroxbuster.json",
            "reconflow/data/wordlists/common.txt",
        )
