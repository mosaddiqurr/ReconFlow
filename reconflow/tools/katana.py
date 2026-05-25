"""Katana integration."""

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from reconflow.core.runner import run_command
from reconflow.models.crawled_url import CrawledUrl
from reconflow.models.endpoint import Endpoint
from reconflow.tools.base import ToolAdapter
from reconflow.tools.jsonl_utils import load_jsonl_records


INTERESTING_URL_MARKERS = (
    "login",
    "admin",
    "api",
    "upload",
    "reset",
    "token",
    "callback",
    "redirect",
)


def load_katana_targets(live_hosts_path: str | Path) -> list[str]:
    """Load Katana target URLs from parsed httpx live hosts."""
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


def write_katana_input(targets: list[str], output_path: str | Path) -> Path:
    """Write live host URLs to a Katana-compatible input file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(targets) + "\n", encoding="utf-8")
    return path


def build_katana_command(
    input_path: str | Path,
    output_jsonl_path: str | Path,
) -> list[str]:
    """Build a conservative Katana crawl command."""
    return [
        "katana",
        "-jsonl",
        "-silent",
        "-d",
        "2",
        "-list",
        str(input_path),
        "-o",
        str(output_jsonl_path),
    ]


def _url_from_record(record: dict[str, Any]) -> str:
    request = record.get("request", {})
    endpoint = request.get("endpoint") if isinstance(request, dict) else None
    return str(record.get("url") or endpoint or "")


def parse_katana_jsonl(
    jsonl_path: str | Path,
    parse_warnings: list[str] | None = None,
) -> list[CrawledUrl]:
    """Parse Katana JSONL output into crawled URL models."""
    crawled_urls: list[CrawledUrl] = []
    seen: set[str] = set()

    for record in load_jsonl_records(jsonl_path, parse_warnings):
        url = _url_from_record(record)
        if not url or url in seen:
            continue

        parsed_url = urlparse(url)
        seen.add(url)
        crawled_urls.append(
            CrawledUrl(
                url=url,
                host=parsed_url.netloc,
                path=parsed_url.path or "/",
                query_params=parse_qs(parsed_url.query),
                source_tool="katana",
            )
        )

    return crawled_urls


def save_crawled_urls_json(
    crawled_urls: list[CrawledUrl],
    output_path: str | Path,
) -> Path:
    """Save parsed crawled URL models as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [crawled_url.model_dump() for crawled_url in crawled_urls]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def is_interesting_crawled_url(crawled_url: CrawledUrl) -> bool:
    """Return whether a crawled URL should be merged into endpoints."""
    return any(marker in crawled_url.url.lower() for marker in INTERESTING_URL_MARKERS)


def _load_existing_endpoints(endpoints_path: Path) -> list[Endpoint]:
    if not endpoints_path.exists():
        return []

    records = json.loads(endpoints_path.read_text(encoding="utf-8"))
    return [Endpoint.model_validate(record) for record in records]


def merge_interesting_crawled_urls_into_endpoints(
    crawled_urls: list[CrawledUrl],
    endpoints_path: str | Path,
) -> list[Endpoint]:
    """Merge interesting Katana URLs into endpoints.json without duplicates."""
    path = Path(endpoints_path)
    endpoints = _load_existing_endpoints(path)
    existing_urls = {endpoint.url for endpoint in endpoints}

    for crawled_url in crawled_urls:
        if crawled_url.url in existing_urls or not is_interesting_crawled_url(crawled_url):
            continue

        endpoints.append(
            Endpoint(
                url=crawled_url.url,
                host=crawled_url.host,
                path=crawled_url.path,
                source_tool="katana",
                interesting=True,
            )
        )
        existing_urls.add(crawled_url.url)

    path.parent.mkdir(parents=True, exist_ok=True)
    data = [endpoint.model_dump() for endpoint in endpoints]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return endpoints


def run_katana(
    scan_folder: str | Path,
    live_hosts_path: str | Path,
    timeout: float | None = None,
):
    """Run Katana against URLs from parsed live hosts."""
    scan_path = Path(scan_folder)
    raw_jsonl_path = scan_path / "raw" / "katana.jsonl"
    input_path = scan_path / "raw" / "katana_input.txt"
    targets = load_katana_targets(live_hosts_path)
    write_katana_input(targets, input_path)
    command = build_katana_command(input_path, raw_jsonl_path)
    return run_command("katana", command, timeout=timeout)


class KatanaTool(ToolAdapter):
    name = "katana"

    def check_available(self) -> bool:
        from shutil import which

        return which("katana") is not None

    def build_command(self, target: str) -> list[str]:
        return [
            "katana",
            "-jsonl",
            "-silent",
            "-d",
            "2",
            "-u",
            target,
            "-o",
            "katana.jsonl",
        ]
