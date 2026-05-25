from pathlib import Path
from tempfile import TemporaryDirectory

from reconflow.models.tool_result import ToolRunResult
from reconflow.tools.gowitness import (
    build_gowitness_command,
    collect_screenshot_metadata,
    load_gowitness_targets,
    parse_gowitness_jsonl,
    parse_gowitness_metadata,
    run_gowitness,
    save_screenshots_json,
    write_gowitness_input,
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

SAMPLE_SCREENSHOT_METADATA = """[
  {
    "url": "https://example.com",
    "host": "example.com",
    "screenshot_path": "screenshots/example.com.png",
    "status": "captured",
    "source_tool": "gowitness"
  }
]
"""


def test_load_gowitness_targets_from_live_hosts() -> None:
    with TemporaryDirectory() as tmp_dir:
        live_hosts_path = Path(tmp_dir) / "live_hosts.json"
        live_hosts_path.write_text(SAMPLE_LIVE_HOSTS_JSON, encoding="utf-8")

        targets = load_gowitness_targets(live_hosts_path)

    assert targets == ["https://example.com", "https://admin.example.com"]


def test_write_gowitness_input() -> None:
    with TemporaryDirectory() as tmp_dir:
        input_path = Path(tmp_dir) / "raw" / "gowitness_input.txt"

        saved_path = write_gowitness_input(
            ["https://example.com", "https://admin.example.com"],
            input_path,
        )
        saved_text = input_path.read_text(encoding="utf-8")

    assert saved_path == input_path
    assert saved_text == "https://example.com\nhttps://admin.example.com\n"


def test_build_gowitness_command() -> None:
    command = build_gowitness_command(
        "scans/scan_001/raw/gowitness_input.txt",
        "scans/scan_001/screenshots",
        "scans/scan_001/raw/gowitness.jsonl",
    )

    assert "--disable-db" not in command
    assert "--screenshot-path" in command
    assert "scans/scan_001/screenshots" in command
    assert "--write-jsonl" in command
    assert "--write-jsonl-file" in command
    assert "scans/scan_001/raw/gowitness.jsonl" in command


def test_build_gowitness_command_falls_back_without_jsonl_file_flag() -> None:
    command = build_gowitness_command(
        "scans/scan_001/raw/gowitness_input.txt",
        "scans/scan_001/screenshots",
        "scans/scan_001/raw/gowitness.jsonl",
        supports_jsonl_file=False,
    )

    assert "--write-jsonl" in command
    assert "--write-jsonl-file" not in command


def test_parse_gowitness_jsonl_fixture() -> None:
    with TemporaryDirectory() as tmp_dir:
        jsonl_path = Path(tmp_dir) / "gowitness.jsonl"
        jsonl_path.write_text(
            '{"url":"https://example.com","host":"example.com","screenshot_path":"screenshots/example.com.png","status":"captured"}\n',
            encoding="utf-8",
        )

        screenshots = parse_gowitness_jsonl(jsonl_path)

    assert len(screenshots) == 1
    assert screenshots[0].url == "https://example.com"
    assert screenshots[0].screenshot_path == "screenshots/example.com.png"


def test_run_gowitness_falls_back_when_jsonl_file_flag_is_unsupported(
    monkeypatch,
) -> None:
    commands: list[list[str]] = []

    def fake_run_command(
        tool_name,
        command,
        timeout=None,
        stdout_path=None,
        stderr_path=None,
    ):
        commands.append(command)
        return ToolRunResult(
            tool_name=tool_name,
            command=command,
            exit_code=1 if len(commands) == 1 else 0,
            stdout="",
            stderr="unknown flag: --write-jsonl-file" if len(commands) == 1 else "",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
            stdout_path=str(stdout_path) if stdout_path else None,
            stderr_path=str(stderr_path) if stderr_path else None,
        )

    monkeypatch.setattr("reconflow.tools.gowitness.run_command", fake_run_command)

    with TemporaryDirectory() as tmp_dir:
        scan_path = Path(tmp_dir)
        live_hosts_path = scan_path / "parsed" / "live_hosts.json"
        live_hosts_path.parent.mkdir()
        live_hosts_path.write_text(SAMPLE_LIVE_HOSTS_JSON, encoding="utf-8")

        result = run_gowitness(scan_path, live_hosts_path)

    assert result.exit_code == 0
    assert "--write-jsonl-file" in commands[0]
    assert "--write-jsonl-file" not in commands[1]


def test_parse_gowitness_metadata_fixture() -> None:
    with TemporaryDirectory() as tmp_dir:
        metadata_path = Path(tmp_dir) / "screenshots.json"
        metadata_path.write_text(SAMPLE_SCREENSHOT_METADATA, encoding="utf-8")

        screenshots = parse_gowitness_metadata(metadata_path)

    assert len(screenshots) == 1
    assert screenshots[0].url == "https://example.com"
    assert screenshots[0].host == "example.com"
    assert screenshots[0].screenshot_path == "screenshots/example.com.png"
    assert screenshots[0].status == "captured"
    assert screenshots[0].source_tool == "gowitness"


def test_collect_screenshot_metadata_from_fake_files() -> None:
    with TemporaryDirectory() as tmp_dir:
        screenshots_dir = Path(tmp_dir) / "screenshots"
        screenshots_dir.mkdir()
        screenshot_path = screenshots_dir / "example.com.png"
        screenshot_path.write_bytes(b"fake png")

        screenshots = collect_screenshot_metadata(
            ["https://example.com", "https://missing.example.com"],
            screenshots_dir,
        )

    assert len(screenshots) == 2
    assert screenshots[0].url == "https://example.com"
    assert screenshots[0].host == "example.com"
    assert screenshots[0].screenshot_path == str(screenshot_path)
    assert screenshots[0].status == "captured"
    assert screenshots[1].host == "missing.example.com"
    assert screenshots[1].screenshot_path == ""
    assert screenshots[1].status == "missing"


def test_save_screenshots_json() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        metadata_path = temp_path / "screenshots.json"
        output_path = temp_path / "parsed" / "screenshots.json"
        metadata_path.write_text(SAMPLE_SCREENSHOT_METADATA, encoding="utf-8")

        screenshots = parse_gowitness_metadata(metadata_path)
        saved_path = save_screenshots_json(screenshots, output_path)
        saved_text = output_path.read_text(encoding="utf-8")

    assert saved_path == output_path
    assert '"host": "example.com"' in saved_text
    assert '"source_tool": "gowitness"' in saved_text
