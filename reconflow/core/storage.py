"""Storage helpers for scan artifacts."""

import json
from pathlib import Path
import re

from reconflow.utils.time_utils import utc_now_iso


SCAN_SUBDIRECTORIES = ("raw", "parsed", "screenshots", "reports")
SCAN_ID_PATTERN = re.compile(r"^scan_(\d{3})_")


def _slugify_target(target: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", target.lower()).strip("_")
    return slug or "target"


def _next_scan_number(base_dir: Path) -> int:
    scan_numbers: list[int] = []
    if not base_dir.exists():
        return 1

    for scan_dir in base_dir.iterdir():
        if not scan_dir.is_dir():
            continue
        match = SCAN_ID_PATTERN.match(scan_dir.name)
        if match:
            scan_numbers.append(int(match.group(1)))

    return max(scan_numbers, default=0) + 1


def ensure_scan_dirs(base_dir: str | Path = "scans") -> None:
    """Create the base scans directory if missing."""
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)


def create_scan_folder(
    target: str,
    target_type: str,
    mode: str,
    base_dir: str | Path = "scans",
    tools_planned: list[str] | None = None,
) -> dict:
    """Create a unique scan folder and write its metadata."""
    base = Path(base_dir)
    ensure_scan_dirs(base)

    scan_number = _next_scan_number(base)
    scan_id = f"scan_{scan_number:03d}_{_slugify_target(target)}"
    scan_dir = base / scan_id
    while scan_dir.exists():
        scan_number += 1
        scan_id = f"scan_{scan_number:03d}_{_slugify_target(target)}"
        scan_dir = base / scan_id

    scan_dir.mkdir(parents=True)
    for directory_name in SCAN_SUBDIRECTORIES:
        (scan_dir / directory_name).mkdir()

    start_time = utc_now_iso()
    end_time = utc_now_iso()
    metadata = {
        "scan_id": scan_id,
        "target": target,
        "target_type": target_type,
        "mode": mode,
        "start_time": start_time,
        "end_time": end_time,
        "status": "initialized",
        "output_dir": str(scan_dir),
        "tools_planned": tools_planned or [],
        "tools_completed": [],
    }
    write_scan_metadata(scan_dir, metadata)
    return metadata


def write_scan_metadata(scan_dir: str | Path, metadata: dict) -> Path:
    """Write scan metadata to metadata.json."""
    metadata_path = Path(scan_dir) / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata_path


def read_scan_metadata(metadata_path: str | Path) -> dict:
    """Read a scan metadata.json file."""
    return json.loads(Path(metadata_path).read_text(encoding="utf-8"))


def read_scan_history(base_dir: str | Path = "scans") -> list[dict]:
    """Read all scan metadata files under the scans directory."""
    base = Path(base_dir)
    if not base.exists():
        return []

    history: list[dict] = []
    for metadata_path in sorted(base.glob("scan_*/metadata.json")):
        history.append(read_scan_metadata(metadata_path))

    return history
