"""WhatWeb integration."""

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reconflow.core.runner import run_command
from reconflow.models.technology import Technology
from reconflow.tools.base import ToolAdapter


def load_whatweb_targets(live_hosts_path: str | Path) -> list[str]:
    """Load WhatWeb target URLs from parsed httpx live hosts."""
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


def build_whatweb_command(
    targets: list[str],
    output_json_path: str | Path,
) -> list[str]:
    """Build a WhatWeb JSON output command."""
    if not targets:
        raise ValueError("targets are required to build a WhatWeb command")
    return ["whatweb", "--log-json", str(output_json_path), *targets]


def _coerce_first_string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        return str(value[0])
    return str(value)


def _coerce_category(plugin_data: dict[str, Any]) -> str | None:
    return _coerce_first_string(
        plugin_data.get("category", plugin_data.get("categories"))
    )


def _coerce_version(plugin_data: dict[str, Any]) -> str | None:
    return _coerce_first_string(plugin_data.get("version"))


def _load_whatweb_records(output_path: str | Path) -> list[dict[str, Any]]:
    text = Path(output_path).read_text(encoding="utf-8").strip()
    if not text:
        return []

    loaded = json.loads(text)
    if isinstance(loaded, list):
        return [record for record in loaded if isinstance(record, dict)]
    if isinstance(loaded, dict):
        return [loaded]
    return []


def parse_whatweb_json(output_path: str | Path) -> list[Technology]:
    """Parse WhatWeb JSON output into technology models."""
    technologies: list[Technology] = []
    for record in _load_whatweb_records(output_path):
        url = str(record.get("target") or record.get("url") or "")
        host = urlparse(url).netloc or url
        plugins = record.get("plugins", {})
        if not isinstance(plugins, dict):
            continue

        for plugin_name, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                plugin_data = {}
            technologies.append(
                Technology(
                    host=host,
                    url=url,
                    name=str(plugin_name),
                    version=_coerce_version(plugin_data),
                    category=_coerce_category(plugin_data),
                    source_tool="whatweb",
                )
            )

    return technologies


def save_technologies_json(
    technologies: list[Technology],
    output_path: str | Path,
) -> Path:
    """Save parsed technology models as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [technology.model_dump() for technology in technologies]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def run_whatweb(
    scan_folder: str | Path,
    live_hosts_path: str | Path,
    timeout: float | None = None,
):
    """Run WhatWeb against URLs from parsed live hosts."""
    scan_path = Path(scan_folder)
    raw_json_path = scan_path / "raw" / "whatweb.json"
    targets = load_whatweb_targets(live_hosts_path)
    command = build_whatweb_command(targets, raw_json_path)
    return run_command("whatweb", command, timeout=timeout)


class WhatwebTool(ToolAdapter):
    name = "whatweb"

    def check_available(self) -> bool:
        from shutil import which

        return which("whatweb") is not None

    def build_command(self, target: str) -> list[str]:
        return build_whatweb_command([target], "whatweb.json")
