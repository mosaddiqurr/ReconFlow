import json
from pathlib import Path
from tempfile import TemporaryDirectory

from typer.testing import CliRunner

from reconflow.cli import app, console, render_raw_cli_results
from reconflow.core.storage import create_scan_folder, read_scan_metadata, write_scan_metadata
from reconflow.reports.json_report import build_raw_report_context
from reconflow.models.tool_result import ToolRunResult

runner = CliRunner()


def tool_result(
    tool_name: str,
    command: list[str] | None = None,
    exit_code: int = 0,
    stderr: str = "",
) -> ToolRunResult:
    return ToolRunResult(
        tool_name=tool_name,
        command=command or [tool_name],
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        start_time="2026-05-18T00:00:00+00:00",
        end_time="2026-05-18T00:00:01+00:00",
        duration_seconds=1.0,
        timed_out=False,
    )


def missing_tool_result(tool_name: str) -> ToolRunResult:
    return tool_result(
        tool_name=tool_name,
        exit_code=127,
        stderr=f"mocked missing {tool_name}",
    )


def mock_missing_web_tools(monkeypatch, tool_names: list[str] | None = None) -> None:
    for tool_name in tool_names or [
        "whatweb",
        "feroxbuster",
        "katana",
        "nuclei",
        "gowitness",
    ]:
        monkeypatch.setattr(
            f"reconflow.cli.run_{tool_name}",
            lambda *args, tool_name=tool_name, **kwargs: missing_tool_result(tool_name),
        )


def mock_malformed_katana_scan(monkeypatch) -> None:
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200}\n'
    )
    sample_katana_jsonl = (
        '{"url":"https://example.com/login"}\n'
        '{"url":"https://example.com/truncated"\n'
        '{"url":"https://example.com/admin"}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        (Path(scan_folder) / "raw" / "subfinder.txt").write_text("", encoding="utf-8")
        return tool_result("subfinder")

    def fail_run_dnsx(scan_folder, subdomains, timeout=None):
        raise AssertionError("dnsx should be skipped")

    def fake_run_nmap(target, scan_folder, timeout=None):
        return missing_tool_result("nmap")

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        (Path(scan_folder) / "raw" / "httpx.jsonl").write_text(
            sample_httpx_jsonl,
            encoding="utf-8",
        )
        return tool_result("httpx")

    def fake_run_katana(scan_folder, live_hosts_path, timeout=None):
        assert Path(live_hosts_path).exists()
        (Path(scan_folder) / "raw" / "katana.jsonl").write_text(
            sample_katana_jsonl,
            encoding="utf-8",
        )
        return tool_result("katana")

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr("reconflow.cli.run_dnsx", fail_run_dnsx)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    mock_missing_web_tools(monkeypatch, ["whatweb", "feroxbuster"])
    monkeypatch.setattr("reconflow.cli.run_katana", fake_run_katana)
    mock_missing_web_tools(monkeypatch, ["nuclei", "gowitness"])


def test_help_shows_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "scan" in result.output
    assert "tools" in result.output
    assert "history" in result.output
    assert "report" in result.output
    assert "compare" in result.output


def test_scan_blocked_without_authorization() -> None:
    result = runner.invoke(app, ["scan", "example.com"])

    assert result.exit_code == 1
    assert "ReconFlow is only for systems you own or have explicit permission to test." in result.output
    assert "Raw Scan Results" not in result.output


def test_scan_allowed_with_authorization(monkeypatch) -> None:
    original_cwd = Path.cwd()

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--i-authorize", "--dry-run"],
            )
            metadata_file = (
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
            scan_path = tmp_path / "scans" / "scan_001_example_com"
            assert metadata_file.exists()
            assert (scan_path / "reports" / "report_raw.md").exists()
            assert (scan_path / "reports" / "report_summary.md").exists()
            assert (scan_path / "reports" / "report.md").exists()
            metadata = read_scan_metadata(metadata_file)
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Summary Scan Results" in result.output
    assert "Workflow Summary" in result.output
    assert "Tool Execution Summary" in result.output
    assert metadata["scan_id"] == "scan_001_example_com"
    assert metadata["target"] == "example.com"
    assert metadata["target_type"] == "domain"
    assert metadata["mode"] == "standard"
    assert metadata["tools_planned"] == [
        "subfinder",
        "dnsx",
        "nmap",
        "httpx",
        "whatweb",
        "feroxbuster",
        "nuclei",
    ]


def test_scan_valid_mode_quick(monkeypatch) -> None:
    original_cwd = Path.cwd()

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--mode",
                    "quick",
                    "--i-authorize",
                    "--dry-run",
                ],
            )
            metadata_file = (
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
            assert metadata_file.exists()
            metadata = read_scan_metadata(metadata_file)
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Summary Scan Results" in result.output
    assert "Workflow Summary" in result.output
    assert metadata["mode"] == "quick"
    assert metadata["tools_planned"] == ["nmap", "httpx"]


def test_scan_explain_dry_run_shows_workflow_decisions(monkeypatch) -> None:
    original_cwd = Path.cwd()

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--mode",
                    "standard",
                    "--explain",
                    "--i-authorize",
                    "--dry-run",
                ],
            )
            metadata = read_scan_metadata(
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Workflow Decision" in result.output
    assert "Skipped dnsx" in result.output
    assert "would run httpx command" in result.output
    assert "Skipped httpx" not in result.output
    assert metadata["mode"] == "standard"


def test_scan_default_view_is_summary(monkeypatch) -> None:
    original_cwd = Path.cwd()

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "deep", "--i-authorize", "--dry-run"],
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Summary Scan Results" in result.output
    assert "Raw Scan Results" not in result.output


def test_scan_view_raw_shows_tool_by_tool_headings(monkeypatch) -> None:
    original_cwd = Path.cwd()

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--mode",
                    "deep",
                    "--i-authorize",
                    "--dry-run",
                    "--view",
                    "raw",
                ],
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Raw Scan Results" in result.output
    assert "Tool-by-Tool Results" in result.output
    assert "Tool 1: subfinder" in result.output
    assert "Tool 9: gowitness" in result.output


def test_scan_view_summary_shows_compact_summary_headings(monkeypatch) -> None:
    original_cwd = Path.cwd()

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--mode",
                    "deep",
                    "--i-authorize",
                    "--dry-run",
                    "--view",
                    "summary",
                ],
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Summary Scan Results" in result.output
    assert "Scan Result" in result.output
    assert "Recommended Next Actions" in result.output
    assert "Tool Execution Summary" in result.output
    assert "Reports saved" in result.output


def test_normal_scan_hides_workflow_summary_and_step_panels(monkeypatch) -> None:
    original_cwd = Path.cwd()

    monkeypatch.setattr(
        "reconflow.cli.run_nmap",
        lambda *args, **kwargs: missing_tool_result("nmap"),
    )
    monkeypatch.setattr(
        "reconflow.cli.run_httpx",
        lambda *args, **kwargs: missing_tool_result("httpx"),
    )

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "quick", "--i-authorize"],
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "[1/2] nmap missing" in result.output
    assert "Summary Scan Results" in result.output
    assert "Workflow Summary" not in result.output
    assert "Step Progress" not in result.output


def test_scan_verbose_shows_detailed_progress_panels(monkeypatch) -> None:
    original_cwd = Path.cwd()

    monkeypatch.setattr(
        "reconflow.cli.run_nmap",
        lambda *args, **kwargs: tool_result("nmap", exit_code=2, stderr="boom"),
    )
    monkeypatch.setattr(
        "reconflow.cli.run_httpx",
        lambda *args, **kwargs: missing_tool_result("httpx"),
    )

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--mode",
                    "quick",
                    "--i-authorize",
                    "--verbose",
                ],
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Workflow Summary" in result.output
    assert "Step Progress" in result.output
    assert "Command Execution Issue" in result.output


def test_scan_invalid_view_fails_cleanly(monkeypatch) -> None:
    original_cwd = Path.cwd()

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--i-authorize", "--view", "executive"],
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 1
    assert "Invalid View" in result.output


def test_scan_invalid_mode(monkeypatch) -> None:
    original_cwd = Path.cwd()

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "invalid", "--i-authorize"],
            )
            scans_dir_exists = (tmp_path / "scans").exists()
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 1
    assert "Invalid scan mode" in result.output
    assert scans_dir_exists is False


def test_history_command_output(monkeypatch) -> None:
    original_cwd = Path.cwd()

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        try:
            monkeypatch.chdir(tmp_path)

            scan_result = runner.invoke(
                app,
                ["scan", "example.com", "--i-authorize", "--dry-run"],
            )

            assert scan_result.exit_code == 0

            result = runner.invoke(app, ["history"])

            history_dir = tmp_path / "scans" / "scan_001_example_com"
            metadata_file = history_dir / "metadata.json"

            assert history_dir.exists()
            assert metadata_file.exists()

        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "ReconFlow Scan History" in result.output


def test_scan_runs_mocked_nmap_and_parses_services(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.24" />
      </port>
    </ports>
  </host>
</nmaprun>
"""

    def fake_run_nmap(target, scan_folder, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "nmap.xml"
        raw_path.write_text(sample_xml, encoding="utf-8")
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", "-sV", "-oX", str(raw_path), target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        return ToolRunResult(
            tool_name="httpx",
            command=["httpx", "-json", "-silent", "-o", "httpx.jsonl", "-u", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing httpx",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "quick", "--i-authorize"],
            )
            parsed_services_path = (
                tmp_path
                / "scans"
                / "scan_001_example_com"
                / "parsed"
                / "services.json"
            )
            metadata = read_scan_metadata(
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
            assert parsed_services_path.exists()
            parsed_services = json.loads(
                parsed_services_path.read_text(encoding="utf-8")
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "What Was Found" in result.output
    assert metadata["tools_completed"] == ["nmap"]
    assert len(parsed_services) == 1
    assert parsed_services[0]["host"] == "93.184.216.34"
    assert parsed_services[0]["port"] == 80
    assert parsed_services[0]["protocol"] == "tcp"
    assert parsed_services[0]["service_name"] == "http"
    assert parsed_services[0]["product"] == "nginx"
    assert parsed_services[0]["version"] == "1.24"
    assert parsed_services[0]["source_tool"] == "nmap"


def test_scan_runs_mocked_httpx_and_parses_live_hosts(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200,'
        '"title":"Example Domain","webserver":"ECS","content_length":1256,'
        '"technologies":["Akamai"]}\n'
    )

    def fake_run_nmap(target, scan_folder, timeout=None):
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", "-sV", "-oX", "nmap.xml", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing nmap",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "httpx.jsonl"
        raw_path.write_text(sample_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="httpx",
            command=["httpx", "-json", "-silent", "-o", str(raw_path), "-u", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "quick", "--i-authorize"],
            )
            parsed_live_hosts_path = (
                tmp_path
                / "scans"
                / "scan_001_example_com"
                / "parsed"
                / "live_hosts.json"
            )
            metadata = read_scan_metadata(
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
            assert parsed_live_hosts_path.exists()
            parsed_live_hosts = json.loads(
                parsed_live_hosts_path.read_text(encoding="utf-8")
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "What Was Found" in result.output
    assert metadata["tools_completed"] == ["httpx"]
    assert len(parsed_live_hosts) == 1
    assert parsed_live_hosts[0]["url"] == "https://example.com"
    assert parsed_live_hosts[0]["host"] == "example.com"
    assert parsed_live_hosts[0]["status_code"] == 200
    assert parsed_live_hosts[0]["title"] == "Example Domain"
    assert parsed_live_hosts[0]["webserver"] == "ECS"
    assert parsed_live_hosts[0]["content_length"] == 1256
    assert parsed_live_hosts[0]["technologies"] == ["Akamai"]
    assert parsed_live_hosts[0]["source_tool"] == "httpx"


def test_scan_runs_mocked_whatweb_from_live_hosts(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200,'
        '"title":"Example Domain","webserver":"ECS","content_length":1256}\n'
    )
    sample_whatweb_json = """[
  {
    "target": "https://example.com",
    "plugins": {
      "nginx": {
        "version": ["1.24.0"],
        "categories": ["Web servers"]
      },
      "jQuery": {
        "version": ["3.7.1"],
        "categories": ["JavaScript libraries"]
      }
    }
  }
]
"""

    def fake_run_subfinder(target, scan_folder, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "subfinder.txt"
        raw_path.write_text("www.example.com\n", encoding="utf-8")
        return ToolRunResult(
            tool_name="subfinder",
            command=["subfinder", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_dnsx(scan_folder, subdomains, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "dnsx.jsonl"
        raw_path.write_text(
            '{"host":"www.example.com","a":["93.184.216.34"]}\n',
            encoding="utf-8",
        )
        return ToolRunResult(
            tool_name="dnsx",
            command=["dnsx", "-json", "-silent", "-l", "dnsx_input.txt"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_nmap(target, scan_folder, timeout=None):
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing nmap",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "httpx.jsonl"
        raw_path.write_text(sample_httpx_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="httpx",
            command=["httpx", "-json", "-silent", "-u", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_whatweb(scan_folder, live_hosts_path, timeout=None):
        live_hosts = json.loads(Path(live_hosts_path).read_text(encoding="utf-8"))
        assert [live_host["url"] for live_host in live_hosts] == [
            "https://example.com"
        ]
        raw_path = Path(scan_folder) / "raw" / "whatweb.json"
        raw_path.write_text(sample_whatweb_json, encoding="utf-8")
        return ToolRunResult(
            tool_name="whatweb",
            command=["whatweb", "--log-json", str(raw_path), "https://example.com"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr("reconflow.cli.run_dnsx", fake_run_dnsx)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    monkeypatch.setattr("reconflow.cli.run_whatweb", fake_run_whatweb)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "standard", "--i-authorize"],
            )
            scan_path = tmp_path / "scans" / "scan_001_example_com"
            parsed_live_hosts_path = scan_path / "parsed" / "live_hosts.json"
            parsed_technologies_path = scan_path / "parsed" / "technologies.json"
            metadata = read_scan_metadata(scan_path / "metadata.json")

            assert parsed_live_hosts_path.exists()
            assert parsed_technologies_path.exists()
            parsed_technologies = json.loads(
                parsed_technologies_path.read_text(encoding="utf-8")
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Important Observations" in result.output
    assert metadata["tools_completed"] == ["subfinder", "dnsx", "httpx", "whatweb"]
    assert len(parsed_technologies) == 2
    assert parsed_technologies[0]["host"] == "example.com"
    assert parsed_technologies[0]["url"] == "https://example.com"
    assert parsed_technologies[0]["name"] == "nginx"
    assert parsed_technologies[0]["version"] == "1.24.0"
    assert parsed_technologies[0]["category"] == "Web servers"
    assert parsed_technologies[0]["source_tool"] == "whatweb"


def test_scan_runs_mocked_feroxbuster_from_live_hosts(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200,'
        '"title":"Example Domain","webserver":"ECS","content_length":1256}\n'
    )
    sample_feroxbuster_jsonl = (
        '{"type":"response","url":"https://example.com/admin","status":200,'
        '"content_length":1024,"words":120,"lines":30}\n'
        '{"type":"response","url":"https://example.com/assets/app.js",'
        '"status_code":200,"content-length":"2048","words":20,"lines":5}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "subfinder.txt"
        raw_path.write_text("www.example.com\n", encoding="utf-8")
        return ToolRunResult(
            tool_name="subfinder",
            command=["subfinder", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_dnsx(scan_folder, subdomains, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "dnsx.jsonl"
        raw_path.write_text(
            '{"host":"www.example.com","a":["93.184.216.34"]}\n',
            encoding="utf-8",
        )
        return ToolRunResult(
            tool_name="dnsx",
            command=["dnsx", "-json", "-silent", "-l", "dnsx_input.txt"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_nmap(target, scan_folder, timeout=None):
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing nmap",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "httpx.jsonl"
        raw_path.write_text(sample_httpx_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="httpx",
            command=["httpx", "-json", "-silent", "-u", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_whatweb(scan_folder, live_hosts_path, timeout=None):
        return ToolRunResult(
            tool_name="whatweb",
            command=["whatweb", "--log-json", "whatweb.json"],
            exit_code=127,
            stdout="",
            stderr="mocked missing whatweb",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_feroxbuster(
        scan_folder,
        live_hosts_path,
        wordlist_path,
        timeout=None,
    ):
        live_hosts = json.loads(Path(live_hosts_path).read_text(encoding="utf-8"))
        assert [live_host["url"] for live_host in live_hosts] == [
            "https://example.com"
        ]
        assert wordlist_path == "custom_words.txt"
        raw_path = Path(scan_folder) / "raw" / "feroxbuster.json"
        raw_path.write_text(sample_feroxbuster_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="feroxbuster",
            command=[
                "feroxbuster",
                "--wordlist",
                wordlist_path,
                "--url",
                "https://example.com",
            ],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr("reconflow.cli.run_dnsx", fake_run_dnsx)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    monkeypatch.setattr("reconflow.cli.run_whatweb", fake_run_whatweb)
    monkeypatch.setattr("reconflow.cli.run_feroxbuster", fake_run_feroxbuster)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--mode",
                    "standard",
                    "--wordlist",
                    "custom_words.txt",
                    "--i-authorize",
                ],
            )
            scan_path = tmp_path / "scans" / "scan_001_example_com"
            parsed_live_hosts_path = scan_path / "parsed" / "live_hosts.json"
            parsed_endpoints_path = scan_path / "parsed" / "endpoints.json"
            metadata = read_scan_metadata(scan_path / "metadata.json")

            assert parsed_live_hosts_path.exists()
            assert parsed_endpoints_path.exists()
            parsed_endpoints = json.loads(
                parsed_endpoints_path.read_text(encoding="utf-8")
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "What Was Found" in result.output
    assert metadata["tools_completed"] == [
        "subfinder",
        "dnsx",
        "httpx",
        "feroxbuster",
    ]
    assert len(parsed_endpoints) == 2
    assert parsed_endpoints[0]["url"] == "https://example.com/admin"
    assert parsed_endpoints[0]["host"] == "example.com"
    assert parsed_endpoints[0]["path"] == "/admin"
    assert parsed_endpoints[0]["status_code"] == 200
    assert parsed_endpoints[0]["content_length"] == 1024
    assert parsed_endpoints[0]["words"] == 120
    assert parsed_endpoints[0]["lines"] == 30
    assert parsed_endpoints[0]["source_tool"] == "feroxbuster"
    assert parsed_endpoints[0]["interesting"] is True
    assert parsed_endpoints[1]["path"] == "/assets/app.js"
    assert parsed_endpoints[1]["interesting"] is False


def test_scan_runs_mocked_katana_from_live_hosts_and_merges_endpoints(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200,'
        '"title":"Example Domain","webserver":"ECS","content_length":1256}\n'
    )
    sample_katana_jsonl = (
        '{"url":"https://example.com/login?redirect=/dashboard"}\n'
        '{"url":"https://example.com/assets/app.js"}\n'
        '{"url":"https://example.com/api/users?token=abc"}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "subfinder.txt"
        raw_path.write_text("www.example.com\n", encoding="utf-8")
        return ToolRunResult(
            tool_name="subfinder",
            command=["subfinder", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_dnsx(scan_folder, subdomains, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "dnsx.jsonl"
        raw_path.write_text(
            '{"host":"www.example.com","a":["93.184.216.34"]}\n',
            encoding="utf-8",
        )
        return ToolRunResult(
            tool_name="dnsx",
            command=["dnsx", "-json", "-silent", "-l", "dnsx_input.txt"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_nmap(target, scan_folder, timeout=None):
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing nmap",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "httpx.jsonl"
        raw_path.write_text(sample_httpx_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="httpx",
            command=["httpx", "-json", "-silent", "-u", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_whatweb(scan_folder, live_hosts_path, timeout=None):
        return ToolRunResult(
            tool_name="whatweb",
            command=["whatweb", "--log-json", "whatweb.json"],
            exit_code=127,
            stdout="",
            stderr="mocked missing whatweb",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_feroxbuster(scan_folder, live_hosts_path, wordlist_path, timeout=None):
        return ToolRunResult(
            tool_name="feroxbuster",
            command=["feroxbuster", "--url", "https://example.com"],
            exit_code=127,
            stdout="",
            stderr="mocked missing feroxbuster",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_gowitness(scan_folder, live_hosts_path, timeout=None):
        return ToolRunResult(
            tool_name="gowitness",
            command=["gowitness", "scan", "--list", "gowitness_input.txt"],
            exit_code=127,
            stdout="",
            stderr="mocked missing gowitness",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_katana(scan_folder, live_hosts_path, timeout=None):
        live_hosts = json.loads(Path(live_hosts_path).read_text(encoding="utf-8"))
        assert [live_host["url"] for live_host in live_hosts] == [
            "https://example.com"
        ]
        raw_path = Path(scan_folder) / "raw" / "katana.jsonl"
        raw_path.write_text(sample_katana_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="katana",
            command=["katana", "-jsonl", "-list", "katana_input.txt"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr("reconflow.cli.run_dnsx", fake_run_dnsx)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    monkeypatch.setattr("reconflow.cli.run_whatweb", fake_run_whatweb)
    monkeypatch.setattr("reconflow.cli.run_feroxbuster", fake_run_feroxbuster)
    monkeypatch.setattr("reconflow.cli.run_gowitness", fake_run_gowitness)
    monkeypatch.setattr("reconflow.cli.run_katana", fake_run_katana)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "deep", "--i-authorize"],
            )
            scan_path = tmp_path / "scans" / "scan_001_example_com"
            parsed_crawled_urls_path = scan_path / "parsed" / "crawled_urls.json"
            parsed_endpoints_path = scan_path / "parsed" / "endpoints.json"
            metadata = read_scan_metadata(scan_path / "metadata.json")

            assert parsed_crawled_urls_path.exists()
            assert parsed_endpoints_path.exists()
            parsed_crawled_urls = json.loads(
                parsed_crawled_urls_path.read_text(encoding="utf-8")
            )
            parsed_endpoints = json.loads(
                parsed_endpoints_path.read_text(encoding="utf-8")
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Important Observations" in result.output
    assert metadata["tools_completed"] == ["subfinder", "dnsx", "httpx", "katana"]
    assert len(parsed_crawled_urls) == 3
    assert parsed_crawled_urls[0]["host"] == "example.com"
    assert parsed_crawled_urls[0]["path"] == "/login"
    assert parsed_crawled_urls[0]["query_params"] == {"redirect": ["/dashboard"]}
    assert len(parsed_endpoints) == 2
    assert (
        parsed_endpoints[0]["url"]
        == "https://example.com/login?redirect=/dashboard"
    )
    assert parsed_endpoints[0]["source_tool"] == "katana"
    assert parsed_endpoints[0]["interesting"] is True
    assert parsed_endpoints[1]["url"] == "https://example.com/api/users?token=abc"


def test_scan_runs_mocked_nuclei_from_live_hosts(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200,'
        '"title":"Example Domain","webserver":"ECS","content_length":1256}\n'
    )
    sample_nuclei_jsonl = (
        '{"template-id":"tech-detect","host":"https://example.com",'
        '"matched-at":"https://example.com","info":{"name":"Technology Detection",'
        '"severity":"info","description":"Detected web technology",'
        '"tags":["tech","fingerprint"]},"matcher-name":"wordpress"}\n'
        '{"template-id":"missing-security-header","host":"https://example.com",'
        '"matched-at":"https://example.com/login","info":{"name":"Missing Security Header",'
        '"severity":"medium","tags":"headers,misconfig"},'
        '"matched-line":"X-Frame-Options missing"}\n'
        '{"template-id":"critical-panel","host":"https://example.com",'
        '"matched-at":"https://example.com/admin","info":{"name":"Exposed Admin Panel",'
        '"severity":"critical","description":"Admin panel exposed"},'
        '"extracted-results":["/admin"]}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "subfinder.txt"
        raw_path.write_text("www.example.com\n", encoding="utf-8")
        return ToolRunResult(
            tool_name="subfinder",
            command=["subfinder", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_dnsx(scan_folder, subdomains, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "dnsx.jsonl"
        raw_path.write_text(
            '{"host":"www.example.com","a":["93.184.216.34"]}\n',
            encoding="utf-8",
        )
        return ToolRunResult(
            tool_name="dnsx",
            command=["dnsx", "-json", "-silent", "-l", "dnsx_input.txt"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_nmap(target, scan_folder, timeout=None):
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing nmap",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "httpx.jsonl"
        raw_path.write_text(sample_httpx_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="httpx",
            command=["httpx", "-json", "-silent", "-u", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_whatweb(scan_folder, live_hosts_path, timeout=None):
        return ToolRunResult(
            tool_name="whatweb",
            command=["whatweb", "--log-json", "whatweb.json"],
            exit_code=127,
            stdout="",
            stderr="mocked missing whatweb",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_feroxbuster(scan_folder, live_hosts_path, wordlist_path, timeout=None):
        return ToolRunResult(
            tool_name="feroxbuster",
            command=["feroxbuster", "--url", "https://example.com"],
            exit_code=127,
            stdout="",
            stderr="mocked missing feroxbuster",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_nuclei(scan_folder, live_hosts_path, timeout=None):
        live_hosts = json.loads(Path(live_hosts_path).read_text(encoding="utf-8"))
        assert [live_host["url"] for live_host in live_hosts] == [
            "https://example.com"
        ]
        raw_path = Path(scan_folder) / "raw" / "nuclei.jsonl"
        raw_path.write_text(sample_nuclei_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="nuclei",
            command=["nuclei", "-jsonl", "-l", "nuclei_input.txt"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr("reconflow.cli.run_dnsx", fake_run_dnsx)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    monkeypatch.setattr("reconflow.cli.run_whatweb", fake_run_whatweb)
    monkeypatch.setattr("reconflow.cli.run_feroxbuster", fake_run_feroxbuster)
    monkeypatch.setattr("reconflow.cli.run_nuclei", fake_run_nuclei)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "standard", "--i-authorize"],
            )
            scan_path = tmp_path / "scans" / "scan_001_example_com"
            parsed_vulnerabilities_path = (
                scan_path / "parsed" / "vulnerabilities.json"
            )
            metadata = read_scan_metadata(scan_path / "metadata.json")

            assert parsed_vulnerabilities_path.exists()
            parsed_vulnerabilities = json.loads(
                parsed_vulnerabilities_path.read_text(encoding="utf-8")
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Vulnerability Summary" in result.output
    assert "What Was Found" in result.output
    assert metadata["tools_completed"] == ["subfinder", "dnsx", "httpx", "nuclei"]
    assert len(parsed_vulnerabilities) == 3
    assert parsed_vulnerabilities[0]["name"] == "Technology Detection"
    assert parsed_vulnerabilities[0]["template_id"] == "tech-detect"
    assert parsed_vulnerabilities[0]["severity"] == "info"
    assert parsed_vulnerabilities[0]["matched_url"] == "https://example.com"
    assert parsed_vulnerabilities[0]["host"] == "https://example.com"
    assert parsed_vulnerabilities[0]["description"] == "Detected web technology"
    assert parsed_vulnerabilities[0]["tags"] == ["tech", "fingerprint"]
    assert parsed_vulnerabilities[0]["evidence"] == {"matcher-name": "wordpress"}
    assert parsed_vulnerabilities[0]["source_tool"] == "nuclei"
    assert parsed_vulnerabilities[1]["severity"] == "medium"
    assert parsed_vulnerabilities[2]["severity"] == "critical"


def test_scan_runs_mocked_gowitness_from_live_hosts(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200,'
        '"title":"Example Domain","webserver":"ECS","content_length":1256}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "subfinder.txt"
        raw_path.write_text("www.example.com\n", encoding="utf-8")
        return ToolRunResult(
            tool_name="subfinder",
            command=["subfinder", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_dnsx(scan_folder, subdomains, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "dnsx.jsonl"
        raw_path.write_text(
            '{"host":"www.example.com","a":["93.184.216.34"]}\n',
            encoding="utf-8",
        )
        return ToolRunResult(
            tool_name="dnsx",
            command=["dnsx", "-json", "-silent", "-l", "dnsx_input.txt"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_nmap(target, scan_folder, timeout=None):
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing nmap",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "httpx.jsonl"
        raw_path.write_text(sample_httpx_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="httpx",
            command=["httpx", "-json", "-silent", "-u", target],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_whatweb(scan_folder, live_hosts_path, timeout=None):
        return ToolRunResult(
            tool_name="whatweb",
            command=["whatweb", "--log-json", "whatweb.json"],
            exit_code=127,
            stdout="",
            stderr="mocked missing whatweb",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_feroxbuster(scan_folder, live_hosts_path, wordlist_path, timeout=None):
        return ToolRunResult(
            tool_name="feroxbuster",
            command=["feroxbuster", "--url", "https://example.com"],
            exit_code=127,
            stdout="",
            stderr="mocked missing feroxbuster",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_katana(scan_folder, live_hosts_path, timeout=None):
        return ToolRunResult(
            tool_name="katana",
            command=["katana", "-jsonl", "-list", "katana_input.txt"],
            exit_code=127,
            stdout="",
            stderr="mocked missing katana",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_nuclei(scan_folder, live_hosts_path, timeout=None):
        return ToolRunResult(
            tool_name="nuclei",
            command=["nuclei", "-jsonl", "-l", "nuclei_input.txt"],
            exit_code=127,
            stdout="",
            stderr="mocked missing nuclei",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_gowitness(scan_folder, live_hosts_path, timeout=None):
        live_hosts = json.loads(Path(live_hosts_path).read_text(encoding="utf-8"))
        assert [live_host["url"] for live_host in live_hosts] == [
            "https://example.com"
        ]
        screenshot_path = Path(scan_folder) / "screenshots" / "example.com.png"
        screenshot_path.write_bytes(b"fake png")
        return ToolRunResult(
            tool_name="gowitness",
            command=["gowitness", "scan", "file", "-f", "gowitness_input.txt"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr("reconflow.cli.run_dnsx", fake_run_dnsx)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    monkeypatch.setattr("reconflow.cli.run_whatweb", fake_run_whatweb)
    monkeypatch.setattr("reconflow.cli.run_feroxbuster", fake_run_feroxbuster)
    monkeypatch.setattr("reconflow.cli.run_katana", fake_run_katana)
    monkeypatch.setattr("reconflow.cli.run_nuclei", fake_run_nuclei)
    monkeypatch.setattr("reconflow.cli.run_gowitness", fake_run_gowitness)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "deep", "--i-authorize"],
            )
            scan_path = tmp_path / "scans" / "scan_001_example_com"
            parsed_screenshots_path = scan_path / "parsed" / "screenshots.json"
            screenshot_path = scan_path / "screenshots" / "example.com.png"
            metadata = read_scan_metadata(scan_path / "metadata.json")

            assert screenshot_path.exists()
            assert parsed_screenshots_path.exists()
            parsed_screenshots = json.loads(
                parsed_screenshots_path.read_text(encoding="utf-8")
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Summary Scan Results" in result.output
    assert "What Was Found" in result.output
    assert "Reports saved" in result.output
    assert metadata["tools_completed"] == ["subfinder", "dnsx", "httpx", "gowitness"]
    assert len(parsed_screenshots) == 1
    assert parsed_screenshots[0]["url"] == "https://example.com"
    assert parsed_screenshots[0]["host"] == "example.com"
    assert parsed_screenshots[0]["screenshot_path"].endswith("example.com.png")
    assert parsed_screenshots[0]["status"] == "captured"
    assert parsed_screenshots[0]["source_tool"] == "gowitness"


def test_deep_scan_with_zero_subdomains_runs_httpx_on_original_domain(
    monkeypatch,
) -> None:
    original_cwd = Path.cwd()
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "subfinder.txt"
        raw_path.write_text("", encoding="utf-8")
        return tool_result("subfinder", ["subfinder", target])

    def fail_run_dnsx(scan_folder, subdomains, timeout=None):
        raise AssertionError("dnsx should be skipped when subfinder returns no assets")

    def fake_run_nmap(target, scan_folder, timeout=None):
        return missing_tool_result("nmap")

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        assert target == "example.com"
        assert resolved_hosts == []
        raw_path = Path(scan_folder) / "raw" / "httpx.jsonl"
        raw_path.write_text(sample_httpx_jsonl, encoding="utf-8")
        return tool_result("httpx", ["httpx", "-u", target])

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr("reconflow.cli.run_dnsx", fail_run_dnsx)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    mock_missing_web_tools(monkeypatch)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "deep", "--i-authorize"],
            )
            scan_path = tmp_path / "scans" / "scan_001_example_com"
            metadata = read_scan_metadata(scan_path / "metadata.json")
            parsed_live_hosts = json.loads(
                (scan_path / "parsed" / "live_hosts.json").read_text(encoding="utf-8")
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert metadata["tools_completed"] == ["subfinder", "httpx"]
    assert {"tool": "dnsx", "reason": "No subdomains are available."} in metadata[
        "tools_skipped"
    ]
    assert parsed_live_hosts[0]["url"] == "https://example.com"


def test_deep_scan_www_domain_uses_apex_for_subfinder_and_original_for_httpx(
    monkeypatch,
) -> None:
    original_cwd = Path.cwd()
    sample_httpx_jsonl = (
        '{"url":"https://www.micratto.com","host":"www.micratto.com",'
        '"status_code":200}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        assert target == "micratto.com"
        raw_path = Path(scan_folder) / "raw" / "subfinder.txt"
        raw_path.write_text("", encoding="utf-8")
        return tool_result("subfinder", ["subfinder", "-d", target])

    def fake_run_nmap(target, scan_folder, timeout=None):
        return missing_tool_result("nmap")

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        assert target == "www.micratto.com"
        assert resolved_hosts == []
        raw_path = Path(scan_folder) / "raw" / "httpx.jsonl"
        raw_path.write_text(sample_httpx_jsonl, encoding="utf-8")
        return tool_result("httpx", ["httpx", "-u", target])

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr(
        "reconflow.cli.run_dnsx",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("dnsx should be skipped")
        ),
    )
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    mock_missing_web_tools(monkeypatch)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "www.micratto.com", "--mode", "deep", "--i-authorize"],
            )
            scan_path = tmp_path / "scans" / "scan_001_www_micratto_com"
            metadata = read_scan_metadata(scan_path / "metadata.json")
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert metadata["target"] == "www.micratto.com"
    assert metadata["tools_completed"] == ["subfinder", "httpx"]


def test_downstream_web_tools_run_after_httpx_creates_live_hosts(monkeypatch) -> None:
    original_cwd = Path.cwd()
    calls: list[str] = []
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        (Path(scan_folder) / "raw" / "subfinder.txt").write_text("", encoding="utf-8")
        return tool_result("subfinder")

    def fake_run_nmap(target, scan_folder, timeout=None):
        return missing_tool_result("nmap")

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        (Path(scan_folder) / "raw" / "httpx.jsonl").write_text(
            sample_httpx_jsonl,
            encoding="utf-8",
        )
        return tool_result("httpx")

    def fake_run_whatweb(scan_folder, live_hosts_path, timeout=None):
        calls.append("whatweb")
        assert Path(live_hosts_path).exists()
        (Path(scan_folder) / "raw" / "whatweb.json").write_text("[]", encoding="utf-8")
        return tool_result("whatweb")

    def fake_run_feroxbuster(scan_folder, live_hosts_path, wordlist_path, timeout=None):
        calls.append("feroxbuster")
        assert Path(live_hosts_path).exists()
        (Path(scan_folder) / "raw" / "feroxbuster.json").write_text(
            "",
            encoding="utf-8",
        )
        return tool_result("feroxbuster")

    def fake_run_katana(scan_folder, live_hosts_path, timeout=None):
        calls.append("katana")
        assert Path(live_hosts_path).exists()
        (Path(scan_folder) / "raw" / "katana.jsonl").write_text("", encoding="utf-8")
        return tool_result("katana")

    def fake_run_nuclei(scan_folder, live_hosts_path, timeout=None):
        calls.append("nuclei")
        assert Path(live_hosts_path).exists()
        (Path(scan_folder) / "raw" / "nuclei.jsonl").write_text("", encoding="utf-8")
        return tool_result("nuclei")

    def fake_run_gowitness(scan_folder, live_hosts_path, timeout=None):
        calls.append("gowitness")
        assert Path(live_hosts_path).exists()
        (Path(scan_folder) / "screenshots" / "example.com.png").write_bytes(b"png")
        return tool_result("gowitness")

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr(
        "reconflow.cli.run_dnsx",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("dnsx should be skipped")
        ),
    )
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    monkeypatch.setattr("reconflow.cli.run_whatweb", fake_run_whatweb)
    monkeypatch.setattr("reconflow.cli.run_feroxbuster", fake_run_feroxbuster)
    monkeypatch.setattr("reconflow.cli.run_katana", fake_run_katana)
    monkeypatch.setattr("reconflow.cli.run_nuclei", fake_run_nuclei)
    monkeypatch.setattr("reconflow.cli.run_gowitness", fake_run_gowitness)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "deep", "--i-authorize"],
            )
            metadata = read_scan_metadata(
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert calls == ["whatweb", "feroxbuster", "katana", "nuclei", "gowitness"]
    assert metadata["tools_completed"] == [
        "subfinder",
        "httpx",
        "whatweb",
        "feroxbuster",
        "katana",
        "nuclei",
        "gowitness",
    ]


def test_scan_does_not_crash_when_katana_output_has_malformed_jsonl(
    monkeypatch,
) -> None:
    original_cwd = Path.cwd()
    mock_malformed_katana_scan(monkeypatch)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "deep", "--i-authorize", "--view", "raw"],
            )
            scan_path = tmp_path / "scans" / "scan_001_example_com"
            metadata = read_scan_metadata(scan_path / "metadata.json")
            crawled_urls = json.loads(
                (scan_path / "parsed" / "crawled_urls.json").read_text(
                    encoding="utf-8"
                )
            )
            raw_katana_exists = (scan_path / "raw" / "katana.jsonl").exists()
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Raw Scan Results" in result.output
    assert "Tool 7: katana" in result.output
    assert "Parse Warning" in result.output
    assert metadata["tools_completed"] == ["subfinder", "httpx", "katana"]
    assert metadata["tools_parse_warnings"] == [
        {"tool": "katana", "message": "Skipped 1 malformed JSONL line"}
    ]
    assert [item["url"] for item in crawled_urls] == [
        "https://example.com/login",
        "https://example.com/admin",
    ]
    assert raw_katana_exists is True


def test_raw_view_caps_and_groups_katana_results(tmp_path) -> None:
    metadata = create_scan_folder(
        target="example.com",
        target_type="domain",
        mode="deep",
        base_dir=tmp_path / "scans",
        tools_planned=["katana"],
    )
    metadata["tools_completed"] = ["katana"]
    scan_path = Path(metadata["output_dir"])
    write_scan_metadata(scan_path, metadata)
    crawled_urls = [
        {"url": f"https://example.com/page-{index}", "path": f"/page-{index}"}
        for index in range(4)
    ]
    crawled_urls.extend(
        [
            {"url": "https://example.com/api/users", "path": "/api/users"},
            {"url": "https://example.com/api/search", "path": "/api/search"},
        ]
    )
    crawled_urls.extend(
        [
            {
                "url": f"https://example.com/_next/static/chunk-{index}.js",
                "path": f"/_next/static/chunk-{index}.js",
            }
            for index in range(8)
        ]
    )
    (scan_path / "parsed" / "crawled_urls.json").write_text(
        json.dumps(crawled_urls),
        encoding="utf-8",
    )
    (scan_path / "parsed" / "findings.json").write_text(
        json.dumps({"overall_risk_score": 0, "findings": []}),
        encoding="utf-8",
    )

    context = build_raw_report_context(scan_path)
    with console.capture() as capture:
        render_raw_cli_results(context)
    output = capture.get()

    assert "Pages:" in output
    assert "API-like endpoints:" in output
    assert "Static assets:" in output
    assert "Showing 10 of 14 results" in output


def test_summary_view_handles_katana_parse_warning(monkeypatch) -> None:
    original_cwd = Path.cwd()
    mock_malformed_katana_scan(monkeypatch)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--mode",
                    "deep",
                    "--i-authorize",
                    "--view",
                    "summary",
                ],
            )
            metadata = read_scan_metadata(
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Summary Scan Results" in result.output
    assert "Tool Execution Summary" in result.output
    assert "Parse warnings" in result.output
    assert "Partially Completed" in result.output
    assert metadata["tools_completed"] == ["subfinder", "httpx", "katana"]
    assert metadata["tools_parse_warnings"] == [
        {"tool": "katana", "message": "Skipped 1 malformed JSONL line"}
    ]


def test_gowitness_failure_does_not_crash_scan(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        (Path(scan_folder) / "raw" / "subfinder.txt").write_text("", encoding="utf-8")
        return tool_result("subfinder")

    def fake_run_nmap(target, scan_folder, timeout=None):
        return missing_tool_result("nmap")

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        (Path(scan_folder) / "raw" / "httpx.jsonl").write_text(
            sample_httpx_jsonl,
            encoding="utf-8",
        )
        return tool_result("httpx")

    def fake_run_gowitness(scan_folder, live_hosts_path, timeout=None):
        return ToolRunResult(
            tool_name="gowitness",
            command=["gowitness", "scan", "file"],
            exit_code=1,
            stdout="",
            stderr="unsupported flag",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr(
        "reconflow.cli.run_dnsx",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("dnsx should be skipped")
        ),
    )
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    mock_missing_web_tools(monkeypatch, ["whatweb", "feroxbuster", "katana", "nuclei"])
    monkeypatch.setattr("reconflow.cli.run_gowitness", fake_run_gowitness)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "deep", "--i-authorize"],
            )
            metadata = read_scan_metadata(
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Issues During Scan" in result.output
    assert {"tool": "gowitness", "reason": "Command failed with exit code 1"} in metadata[
        "tools_failed"
    ]


def test_nmap_web_ports_allow_httpx_fallback(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open" />
        <service name="http-proxy" />
      </port>
    </ports>
  </host>
</nmaprun>
"""
    sample_httpx_jsonl = (
        '{"url":"http://example.com:8080","host":"example.com","status_code":200}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        (Path(scan_folder) / "raw" / "subfinder.txt").write_text("", encoding="utf-8")
        return tool_result("subfinder")

    def fake_run_nmap(target, scan_folder, timeout=None):
        (Path(scan_folder) / "raw" / "nmap.xml").write_text(sample_xml, encoding="utf-8")
        return tool_result("nmap")

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        assert target == "example.com"
        assert resolved_hosts == []
        (Path(scan_folder) / "raw" / "httpx.jsonl").write_text(
            sample_httpx_jsonl,
            encoding="utf-8",
        )
        return tool_result("httpx")

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr(
        "reconflow.cli.run_dnsx",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("dnsx should be skipped")
        ),
    )
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    mock_missing_web_tools(monkeypatch)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--mode",
                    "deep",
                    "--explain",
                    "--i-authorize",
                ],
            )
            metadata = read_scan_metadata(
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Nmap found web ports" in result.output
    assert metadata["tools_completed"] == ["subfinder", "nmap", "httpx"]


def test_missing_nuclei_skips_cleanly_while_other_downstream_tools_run(
    monkeypatch,
) -> None:
    original_cwd = Path.cwd()
    sample_httpx_jsonl = (
        '{"url":"https://example.com","host":"example.com","status_code":200}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        (Path(scan_folder) / "raw" / "subfinder.txt").write_text("", encoding="utf-8")
        return tool_result("subfinder")

    def fake_run_nmap(target, scan_folder, timeout=None):
        return missing_tool_result("nmap")

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        (Path(scan_folder) / "raw" / "httpx.jsonl").write_text(
            sample_httpx_jsonl,
            encoding="utf-8",
        )
        return tool_result("httpx")

    def fake_run_whatweb(scan_folder, live_hosts_path, timeout=None):
        (Path(scan_folder) / "raw" / "whatweb.json").write_text("[]", encoding="utf-8")
        return tool_result("whatweb")

    def fake_run_feroxbuster(scan_folder, live_hosts_path, wordlist_path, timeout=None):
        (Path(scan_folder) / "raw" / "feroxbuster.json").write_text(
            "",
            encoding="utf-8",
        )
        return tool_result("feroxbuster")

    def fake_run_katana(scan_folder, live_hosts_path, timeout=None):
        (Path(scan_folder) / "raw" / "katana.jsonl").write_text("", encoding="utf-8")
        return tool_result("katana")

    def fake_run_gowitness(scan_folder, live_hosts_path, timeout=None):
        (Path(scan_folder) / "screenshots" / "example.com.png").write_bytes(b"png")
        return tool_result("gowitness")

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr(
        "reconflow.cli.run_dnsx",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("dnsx should be skipped")
        ),
    )
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)
    monkeypatch.setattr("reconflow.cli.run_whatweb", fake_run_whatweb)
    monkeypatch.setattr("reconflow.cli.run_feroxbuster", fake_run_feroxbuster)
    monkeypatch.setattr("reconflow.cli.run_katana", fake_run_katana)
    monkeypatch.setattr(
        "reconflow.cli.run_nuclei",
        lambda *args, **kwargs: missing_tool_result("nuclei"),
    )
    monkeypatch.setattr("reconflow.cli.run_gowitness", fake_run_gowitness)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "deep", "--i-authorize"],
            )
            metadata = read_scan_metadata(
                tmp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert metadata["tools_completed"] == [
        "subfinder",
        "httpx",
        "whatweb",
        "feroxbuster",
        "katana",
        "gowitness",
    ]
    assert {"tool": "nuclei", "reason": "Missing external tool"} in metadata[
        "tools_skipped"
    ]


def test_scan_runs_mocked_subfinder_and_dnsx_for_domain(monkeypatch) -> None:
    original_cwd = Path.cwd()
    sample_subfinder_output = "www.example.com\napi.example.com\n"
    sample_dnsx_jsonl = (
        '{"host":"www.example.com","a":["93.184.216.34"]}\n'
        '{"host":"api.example.com","a":["93.184.216.35"]}\n'
    )

    def fake_run_subfinder(target, scan_folder, timeout=None):
        raw_path = Path(scan_folder) / "raw" / "subfinder.txt"
        raw_path.write_text(sample_subfinder_output, encoding="utf-8")
        return ToolRunResult(
            tool_name="subfinder",
            command=["subfinder", "-silent", "-d", target, "-o", str(raw_path)],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_dnsx(scan_folder, subdomains, timeout=None):
        assert subdomains == ["www.example.com", "api.example.com"]
        raw_path = Path(scan_folder) / "raw" / "dnsx.jsonl"
        raw_path.write_text(sample_dnsx_jsonl, encoding="utf-8")
        return ToolRunResult(
            tool_name="dnsx",
            command=["dnsx", "-json", "-silent", "-l", "dnsx_input.txt"],
            exit_code=0,
            stdout="",
            stderr="",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_nmap(target, scan_folder, timeout=None):
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing nmap",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        assert resolved_hosts == ["www.example.com", "api.example.com"]
        return ToolRunResult(
            tool_name="httpx",
            command=["httpx", "-json", "-silent", "-u", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing httpx",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_subfinder", fake_run_subfinder)
    monkeypatch.setattr("reconflow.cli.run_dnsx", fake_run_dnsx)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "standard", "--i-authorize"],
            )
            scan_path = tmp_path / "scans" / "scan_001_example_com"
            parsed_subdomains_path = scan_path / "parsed" / "subdomains.json"
            parsed_assets_path = scan_path / "parsed" / "assets.json"
            metadata = read_scan_metadata(scan_path / "metadata.json")

            assert parsed_subdomains_path.exists()
            assert parsed_assets_path.exists()
            parsed_subdomains = json.loads(
                parsed_subdomains_path.read_text(encoding="utf-8")
            )
            parsed_assets = json.loads(parsed_assets_path.read_text(encoding="utf-8"))
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Summary Scan Results" in result.output
    assert metadata["tools_completed"] == ["subfinder", "dnsx"]
    assert parsed_subdomains == ["www.example.com", "api.example.com"]
    assert len(parsed_assets) == 2
    assert parsed_assets[0]["hostname"] == "www.example.com"
    assert parsed_assets[0]["ip"] == "93.184.216.34"
    assert parsed_assets[0]["record_type"] == "A"
    assert parsed_assets[0]["source_tool"] == "dnsx"
    assert parsed_assets[0]["is_resolved"] is True


def test_scan_skips_subfinder_and_dnsx_for_ip_target(monkeypatch) -> None:
    original_cwd = Path.cwd()

    def fail_run_subfinder(target, scan_folder, timeout=None):
        raise AssertionError("Subfinder should not run for IP targets")

    def fail_run_dnsx(scan_folder, subdomains, timeout=None):
        raise AssertionError("dnsx should not run without parsed subdomains")

    def fake_run_nmap(target, scan_folder, timeout=None):
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing nmap",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        return ToolRunResult(
            tool_name="httpx",
            command=["httpx", "-json", "-silent", "-u", target],
            exit_code=127,
            stdout="",
            stderr="mocked missing httpx",
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    monkeypatch.setattr("reconflow.cli.run_subfinder", fail_run_subfinder)
    monkeypatch.setattr("reconflow.cli.run_dnsx", fail_run_dnsx)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["scan", "93.184.216.34", "--mode", "standard", "--i-authorize"],
            )
            scan_path = tmp_path / "scans" / "scan_001_93_184_216_34"
            metadata = read_scan_metadata(scan_path / "metadata.json")

            assert not (scan_path / "parsed" / "subdomains.json").exists()
            assert not (scan_path / "parsed" / "assets.json").exists()
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Summary Scan Results" in result.output
    assert metadata["target_type"] == "ip"
    assert metadata["tools_completed"] == []
