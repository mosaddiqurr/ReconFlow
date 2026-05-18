"""Gowitness integration."""

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reconflow.core.runner import run_command
from reconflow.models.screenshot import Screenshot
from reconflow.tools.base import ToolAdapter


def load_gowitness_targets(live_hosts_path: str | Path) -> list[str]:
    """Load Gowitness target URLs from parsed httpx live hosts."""
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


def write_gowitness_input(targets: list[str], output_path: str | Path) -> Path:
    """Write live host URLs to a Gowitness-compatible input file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(targets) + "\n", encoding="utf-8")
    return path


def build_gowitness_command(
    input_path: str | Path,
    screenshots_dir: str | Path,
) -> list[str]:
    """Build a Gowitness screenshot command."""
    return [
        "gowitness",
        "scan",
        "file",
        "-f",
        str(input_path),
        "--screenshot-path",
        str(screenshots_dir),
        "--disable-db",
    ]


def _status_from_record(record: dict[str, Any]) -> str:
    value = record.get("status", record.get("status_code", "captured"))
    return str(value)


def _path_from_record(record: dict[str, Any]) -> str:
    return str(
        record.get(
            "screenshot_path",
            record.get("screenshot", record.get("path", "")),
        )
    )


def parse_gowitness_metadata(metadata_path: str | Path) -> list[Screenshot]:
    """Parse Gowitness screenshot metadata into screenshot models."""
    text = Path(metadata_path).read_text(encoding="utf-8").strip()
    if not text:
        return []

    loaded = json.loads(text)
    records = loaded if isinstance(loaded, list) else [loaded]
    screenshots: list[Screenshot] = []

    for record in records:
        if not isinstance(record, dict):
            continue
        url = str(record.get("url", ""))
        parsed_url = urlparse(url)
        screenshots.append(
            Screenshot(
                url=url,
                host=str(record.get("host") or parsed_url.netloc),
                screenshot_path=_path_from_record(record),
                status=_status_from_record(record),
                source_tool="gowitness",
            )
        )

    return screenshots


def _screenshot_name_candidates(url: str) -> list[str]:
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    safe_url = (
        url.replace("://", "_")
        .replace("/", "_")
        .replace("?", "_")
        .replace("&", "_")
        .replace("=", "_")
        .strip("_")
    )
    return [host, safe_url]


def _find_screenshot_path(url: str, screenshots_dir: Path) -> Path | None:
    if not screenshots_dir.exists():
        return None

    candidates = _screenshot_name_candidates(url)
    for screenshot_path in sorted(screenshots_dir.glob("*")):
        if not screenshot_path.is_file():
            continue
        name = screenshot_path.name
        if any(candidate and candidate in name for candidate in candidates):
            return screenshot_path

    return None


def collect_screenshot_metadata(
    targets: list[str],
    screenshots_dir: str | Path,
) -> list[Screenshot]:
    """Build screenshot metadata from expected targets and saved files."""
    directory = Path(screenshots_dir)
    screenshots: list[Screenshot] = []
    for url in targets:
        parsed_url = urlparse(url)
        screenshot_path = _find_screenshot_path(url, directory)
        screenshots.append(
            Screenshot(
                url=url,
                host=parsed_url.netloc,
                screenshot_path=str(screenshot_path) if screenshot_path else "",
                status="captured" if screenshot_path else "missing",
                source_tool="gowitness",
            )
        )

    return screenshots


def save_screenshots_json(
    screenshots: list[Screenshot],
    output_path: str | Path,
) -> Path:
    """Save screenshot metadata as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [screenshot.model_dump() for screenshot in screenshots]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def run_gowitness(
    scan_folder: str | Path,
    live_hosts_path: str | Path,
    timeout: float | None = None,
):
    """Run Gowitness against URLs from parsed live hosts."""
    scan_path = Path(scan_folder)
    screenshots_dir = scan_path / "screenshots"
    input_path = scan_path / "raw" / "gowitness_input.txt"
    targets = load_gowitness_targets(live_hosts_path)
    write_gowitness_input(targets, input_path)
    command = build_gowitness_command(input_path, screenshots_dir)
    return run_command("gowitness", command, timeout=timeout)


class GowitnessTool(ToolAdapter):
    name = "gowitness"

    def check_available(self) -> bool:
        from shutil import which

        return which("gowitness") is not None

    def build_command(self, target: str) -> list[str]:
        return [
            "gowitness",
            "scan",
            "single",
            "--url",
            target,
            "--screenshot-path",
            "screenshots",
            "--disable-db",
        ]
