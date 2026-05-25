from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from reconflow.tools.feroxbuster import (
    build_feroxbuster_command,
    is_interesting_path,
    load_feroxbuster_targets,
    parse_feroxbuster_json,
    save_endpoints_json,
)


SAMPLE_LIVE_HOSTS_JSON = """[
  {
    "url": "https://example.com",
    "host": "example.com",
    "status_code": 200,
    "source_tool": "httpx"
  },
  {
    "url": "https://admin.example.com",
    "host": "admin.example.com",
    "status_code": 200,
    "source_tool": "httpx"
  }
]
"""

SAMPLE_FEROXBUSTER_JSONL = """{"type":"response","url":"https://example.com/admin","status":200,"content_length":1024,"words":120,"lines":30}
{"type":"response","url":"https://example.com/assets/app.js","status_code":200,"content-length":"2048","words":20,"lines":5}
{"type":"scan_complete","url":"https://example.com"}
"""


def test_load_feroxbuster_targets_from_live_hosts() -> None:
    with TemporaryDirectory() as tmp_dir:
        live_hosts_path = Path(tmp_dir) / "live_hosts.json"
        live_hosts_path.write_text(SAMPLE_LIVE_HOSTS_JSON, encoding="utf-8")

        targets = load_feroxbuster_targets(live_hosts_path)

    assert targets == ["https://example.com", "https://admin.example.com"]


def test_build_feroxbuster_command() -> None:
    command = build_feroxbuster_command(
        ["https://example.com", "https://admin.example.com"],
        "scans/scan_001/raw/feroxbuster.json",
        "reconflow/data/wordlists/common.txt",
    )

    assert command == [
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
        "reconflow/data/wordlists/common.txt",
        "-o",
        "scans/scan_001/raw/feroxbuster.json",
        "--url",
        "https://example.com",
        "--url",
        "https://admin.example.com",
    ]


def test_build_feroxbuster_command_requires_targets() -> None:
    with pytest.raises(ValueError):
        build_feroxbuster_command([], "feroxbuster.json", "common.txt")


def test_interesting_path_markers() -> None:
    assert is_interesting_path("/admin")
    assert is_interesting_path("/api/v1/users")
    assert is_interesting_path("/wp-admin/index.php")
    assert not is_interesting_path("/assets/app.js")


def test_parse_feroxbuster_json_fixture() -> None:
    with TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "feroxbuster.json"
        output_path.write_text(SAMPLE_FEROXBUSTER_JSONL, encoding="utf-8")

        endpoints = parse_feroxbuster_json(output_path)

    assert len(endpoints) == 2
    assert endpoints[0].url == "https://example.com/admin"
    assert endpoints[0].host == "example.com"
    assert endpoints[0].path == "/admin"
    assert endpoints[0].status_code == 200
    assert endpoints[0].content_length == 1024
    assert endpoints[0].words == 120
    assert endpoints[0].lines == 30
    assert endpoints[0].source_tool == "feroxbuster"
    assert endpoints[0].interesting is True
    assert endpoints[1].path == "/assets/app.js"
    assert endpoints[1].content_length == 2048
    assert endpoints[1].interesting is False


def test_parse_feroxbuster_json_skips_malformed_jsonl_line() -> None:
    warnings: list[str] = []
    with TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "feroxbuster.json"
        output_path.write_text(
            '{"type":"response","url":"https://example.com/admin","status":200}\n'
            '{"type":"response","url":"https://example.com/broken"\n',
            encoding="utf-8",
        )

        endpoints = parse_feroxbuster_json(output_path, parse_warnings=warnings)

    assert len(endpoints) == 1
    assert endpoints[0].url == "https://example.com/admin"
    assert warnings == ["Skipped 1 malformed JSONL line"]


def test_save_endpoints_json() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        output_path = temp_path / "feroxbuster.json"
        endpoints_path = temp_path / "parsed" / "endpoints.json"
        output_path.write_text(SAMPLE_FEROXBUSTER_JSONL, encoding="utf-8")

        endpoints = parse_feroxbuster_json(output_path)
        saved_path = save_endpoints_json(endpoints, endpoints_path)
        saved_text = endpoints_path.read_text(encoding="utf-8")

    assert saved_path == endpoints_path
    assert '"path": "/admin"' in saved_text
    assert '"source_tool": "feroxbuster"' in saved_text
