"""Nuclei integration."""

import json
from pathlib import Path
from typing import Any

from reconflow.core.runner import run_command
from reconflow.models.vulnerability import Vulnerability
from reconflow.tools.base import ToolAdapter
from reconflow.tools.jsonl_utils import load_jsonl_records


SAFE_EXCLUDED_TAGS = (
    "intrusive",
    "brute-force",
    "bruteforce",
    "destructive",
    "dos",
    "fuzz",
    "fuzzing",
)


def load_nuclei_targets(live_hosts_path: str | Path) -> list[str]:
    """Load Nuclei target URLs from parsed httpx live hosts."""
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


def write_nuclei_input(targets: list[str], output_path: str | Path) -> Path:
    """Write live host URLs to a Nuclei-compatible input file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(targets) + "\n", encoding="utf-8")
    return path


def build_nuclei_command(
    input_path: str | Path,
    output_jsonl_path: str | Path,
) -> list[str]:
    """Build a conservative Nuclei detection-only command."""
    return [
        "nuclei",
        "-jsonl",
        "-silent",
        "-l",
        str(input_path),
        "-o",
        str(output_jsonl_path),
        "-severity",
        "info,low,medium,high,critical",
        "-exclude-tags",
        ",".join(SAFE_EXCLUDED_TAGS),
        "-rl",
        "25",
        "-c",
        "10",
        "-retries",
        "1",
        "-timeout",
        "5",
    ]


def _coerce_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [tag.strip() for tag in str(value).split(",") if tag.strip()]


def _evidence_from_record(record: dict[str, Any]) -> dict[str, Any]:
    evidence_keys = (
        "matcher-name",
        "matched-line",
        "extracted-results",
        "ip",
        "type",
    )
    return {key: record[key] for key in evidence_keys if key in record}


def parse_nuclei_jsonl(
    jsonl_path: str | Path,
    parse_warnings: list[str] | None = None,
) -> list[Vulnerability]:
    """Parse Nuclei JSONL output into vulnerability models."""
    vulnerabilities: list[Vulnerability] = []
    for record in load_jsonl_records(jsonl_path, parse_warnings):
        info = record.get("info", {})
        if not isinstance(info, dict):
            info = {}

        vulnerabilities.append(
            Vulnerability(
                name=str(info.get("name") or record.get("template-id") or ""),
                template_id=str(record.get("template-id", "")),
                severity=str(info.get("severity", "unknown")).lower(),
                matched_url=str(record.get("matched-at") or record.get("host") or ""),
                host=str(record.get("host", "")),
                description=info.get("description"),
                tags=_coerce_tags(info.get("tags")),
                evidence=_evidence_from_record(record),
                source_tool="nuclei",
            )
        )

    return vulnerabilities


def save_vulnerabilities_json(
    vulnerabilities: list[Vulnerability],
    output_path: str | Path,
) -> Path:
    """Save parsed vulnerability models as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [vulnerability.model_dump() for vulnerability in vulnerabilities]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def run_nuclei(
    scan_folder: str | Path,
    live_hosts_path: str | Path,
    timeout: float | None = None,
):
    """Run Nuclei against URLs from parsed live hosts."""
    scan_path = Path(scan_folder)
    raw_jsonl_path = scan_path / "raw" / "nuclei.jsonl"
    input_path = scan_path / "raw" / "nuclei_input.txt"
    targets = load_nuclei_targets(live_hosts_path)
    write_nuclei_input(targets, input_path)
    command = build_nuclei_command(input_path, raw_jsonl_path)
    return run_command("nuclei", command, timeout=timeout)


class NucleiTool(ToolAdapter):
    name = "nuclei"

    def check_available(self) -> bool:
        from shutil import which

        return which("nuclei") is not None

    def build_command(self, target: str) -> list[str]:
        return [
            "nuclei",
            "-jsonl",
            "-silent",
            "-u",
            target,
            "-severity",
            "info,low,medium,high,critical",
            "-exclude-tags",
            ",".join(SAFE_EXCLUDED_TAGS),
        ]
