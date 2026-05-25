from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from reconflow.tools.httpx import (
    build_httpx_command,
    parse_httpx_jsonl,
    save_live_hosts_json,
    select_httpx_inputs,
)


SAMPLE_HTTPX_JSONL = """{"url":"https://example.com","host":"example.com","status_code":200,"title":"Example Domain","webserver":"ECS","content_length":1256,"technologies":["Akamai"]}
{"url":"http://test.example.com","input":"test.example.com","status_code":301,"title":"","server":"nginx","content-length":"178","tech":["nginx"]}
"""


def test_select_httpx_inputs_prefers_resolved_hosts() -> None:
    assert select_httpx_inputs("example.com") == ["example.com"]
    assert select_httpx_inputs("example.com", ["a.example.com", "b.example.com"]) == [
        "a.example.com",
        "b.example.com",
    ]


def test_build_httpx_command_single_input() -> None:
    command = build_httpx_command(["example.com"], "scans/scan_001/raw/httpx.jsonl")

    assert command == [
        "httpx",
        "-json",
        "-silent",
        "-o",
        "scans/scan_001/raw/httpx.jsonl",
        "-u",
        "example.com",
    ]


def test_build_httpx_command_multiple_inputs_requires_input_file() -> None:
    with pytest.raises(ValueError):
        build_httpx_command(["a.example.com", "b.example.com"], "httpx.jsonl")


def test_build_httpx_command_multiple_inputs() -> None:
    command = build_httpx_command(
        ["a.example.com", "b.example.com"],
        "httpx.jsonl",
        "inputs.txt",
    )

    assert command == ["httpx", "-json", "-silent", "-o", "httpx.jsonl", "-l", "inputs.txt"]


def test_parse_httpx_jsonl_fixture() -> None:
    with TemporaryDirectory() as tmp_dir:
        jsonl_path = Path(tmp_dir) / "httpx.jsonl"
        jsonl_path.write_text(SAMPLE_HTTPX_JSONL, encoding="utf-8")

        live_hosts = parse_httpx_jsonl(jsonl_path)

    assert len(live_hosts) == 2
    assert live_hosts[0].url == "https://example.com"
    assert live_hosts[0].host == "example.com"
    assert live_hosts[0].status_code == 200
    assert live_hosts[0].title == "Example Domain"
    assert live_hosts[0].webserver == "ECS"
    assert live_hosts[0].content_length == 1256
    assert live_hosts[0].technologies == ["Akamai"]
    assert live_hosts[0].source_tool == "httpx"
    assert live_hosts[1].host == "test.example.com"
    assert live_hosts[1].webserver == "nginx"
    assert live_hosts[1].content_length == 178


def test_save_live_hosts_json() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        jsonl_path = temp_path / "httpx.jsonl"
        output_path = temp_path / "parsed" / "live_hosts.json"
        jsonl_path.write_text(SAMPLE_HTTPX_JSONL, encoding="utf-8")

        live_hosts = parse_httpx_jsonl(jsonl_path)
        saved_path = save_live_hosts_json(live_hosts, output_path)
        saved_text = output_path.read_text(encoding="utf-8")

    assert saved_path == output_path
    assert '"url": "https://example.com"' in saved_text
    assert '"source_tool": "httpx"' in saved_text
