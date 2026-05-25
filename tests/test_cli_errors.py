from pathlib import Path
from tempfile import TemporaryDirectory

from typer.testing import CliRunner

from reconflow.cli import app
from reconflow.core.storage import create_scan_folder, read_scan_metadata
from reconflow.models.tool_result import ToolRunResult
from reconflow.utils.command_utils import RequiredTool, ToolCheckResult


runner = CliRunner()


def _tool_result(tool_name: str, exit_code: int, timed_out: bool = False) -> ToolRunResult:
    return ToolRunResult(
        tool_name=tool_name,
        command=[tool_name, "example.com"],
        exit_code=exit_code,
        stdout="",
        stderr="simulated command issue" if exit_code != 0 else "",
        start_time="2026-05-18T00:00:00+00:00",
        end_time="2026-05-18T00:00:01+00:00",
        duration_seconds=1.0,
        timed_out=timed_out,
    )


def _fake_tool_check(tool_name: str, installed: bool) -> ToolCheckResult:
    return ToolCheckResult(
        tool=RequiredTool(
            name=tool_name,
            purpose="Network and service discovery",
            command=tool_name,
            install_note=f"Install {tool_name} before running this step.",
        ),
        is_installed=installed,
        detected_path=f"C:/Tools/{tool_name}.exe" if installed else None,
    )


def test_report_missing_scan_id_has_clear_error(monkeypatch) -> None:
    original_cwd = Path.cwd()
    with TemporaryDirectory() as tmp_dir:
        try:
            monkeypatch.chdir(Path(tmp_dir))
            result = runner.invoke(app, ["report", "scan_999_missing"])
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 1
    assert "Missing Scan ID" in result.output
    assert "scan_999_missing" in result.output


def test_report_missing_parsed_data_has_clear_error(monkeypatch) -> None:
    original_cwd = Path.cwd()
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(temp_path)
            create_scan_folder(
                target="example.com",
                target_type="domain",
                mode="quick",
                base_dir=temp_path / "scans",
                tools_planned=["nmap"],
            )
            result = runner.invoke(app, ["report", "scan_001_example_com"])
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 1
    assert "Missing Parsed Data" in result.output
    assert "scan_001_example_com" in result.output


def test_scan_reports_missing_external_tool(monkeypatch) -> None:
    original_cwd = Path.cwd()

    def fake_check_required_tools():
        return [_fake_tool_check("nmap", installed=False)]

    def fake_run_nmap(target, scan_folder, timeout=None):
        return _tool_result("nmap", 127)

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        return _tool_result("httpx", 0)

    monkeypatch.setattr("reconflow.cli.check_required_tools", fake_check_required_tools)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)

    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(temp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "quick", "--i-authorize"],
            )
            metadata = read_scan_metadata(
                temp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "[1/2] nmap missing" in result.output
    assert "Issues During Scan" in result.output
    assert "Missing" in result.output
    assert metadata["tools_skipped"][0]["tool"] == "nmap"


def test_scan_reports_failed_command(monkeypatch) -> None:
    original_cwd = Path.cwd()

    def fake_check_required_tools():
        return [_fake_tool_check("nmap", installed=True)]

    def fake_run_nmap(target, scan_folder, timeout=None):
        return _tool_result("nmap", 2)

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        return _tool_result("httpx", 0)

    monkeypatch.setattr("reconflow.cli.check_required_tools", fake_check_required_tools)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)

    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(temp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "quick", "--i-authorize"],
            )
            metadata = read_scan_metadata(
                temp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "[1/2] nmap failed" in result.output
    assert "Issues During Scan" in result.output
    assert metadata["tools_failed"][0]["reason"] == "Command failed with exit code 2"


def test_scan_reports_timeout(monkeypatch) -> None:
    original_cwd = Path.cwd()

    def fake_check_required_tools():
        return [_fake_tool_check("nmap", installed=True)]

    def fake_run_nmap(target, scan_folder, timeout=None):
        return _tool_result("nmap", -1, timed_out=True)

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        return _tool_result("httpx", 0)

    monkeypatch.setattr("reconflow.cli.check_required_tools", fake_check_required_tools)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)

    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(temp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "quick", "--i-authorize"],
            )
            metadata = read_scan_metadata(
                temp_path / "scans" / "scan_001_example_com" / "metadata.json"
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "[1/2] nmap timed out" in result.output
    assert "Issues During Scan" in result.output
    assert metadata["tools_failed"][0]["reason"] == "Command timed out"


def test_scan_truncates_long_stderr_and_saves_full_artifact(monkeypatch) -> None:
    original_cwd = Path.cwd()
    long_stderr = "\n".join(f"help output line {index}" for index in range(30))

    def fake_check_required_tools():
        return [_fake_tool_check("nmap", installed=True)]

    def fake_run_nmap(target, scan_folder, timeout=None):
        return ToolRunResult(
            tool_name="nmap",
            command=["nmap", "example.com"],
            exit_code=2,
            stdout="",
            stderr=long_stderr,
            start_time="2026-05-18T00:00:00+00:00",
            end_time="2026-05-18T00:00:01+00:00",
            duration_seconds=1.0,
            timed_out=False,
        )

    def fake_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        return _tool_result("httpx", 0)

    monkeypatch.setattr("reconflow.cli.check_required_tools", fake_check_required_tools)
    monkeypatch.setattr("reconflow.cli.run_nmap", fake_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fake_run_httpx)

    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(temp_path)
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "quick", "--i-authorize"],
            )
            stderr_path = (
                temp_path
                / "scans"
                / "scan_001_example_com"
                / "raw"
                / "nmap.stderr.txt"
            )
            saved_stderr = stderr_path.read_text(encoding="utf-8")
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "[1/2] nmap failed" in result.output
    assert "Issues During Scan" in result.output
    assert "Full error saved" in result.output
    assert "help output line 0" not in result.output
    assert "help output line 20" not in result.output
    assert saved_stderr == long_stderr


def test_dry_run_does_not_execute_external_tools(monkeypatch) -> None:
    original_cwd = Path.cwd()

    def fail_run_nmap(target, scan_folder, timeout=None):
        raise AssertionError("dry-run should not execute nmap")

    def fail_run_httpx(target, scan_folder, resolved_hosts=None, timeout=None):
        raise AssertionError("dry-run should not execute httpx")

    monkeypatch.setattr("reconflow.cli.run_nmap", fail_run_nmap)
    monkeypatch.setattr("reconflow.cli.run_httpx", fail_run_httpx)

    with TemporaryDirectory() as tmp_dir:
        try:
            monkeypatch.chdir(Path(tmp_dir))
            result = runner.invoke(
                app,
                ["scan", "example.com", "--mode", "quick", "--i-authorize", "--dry-run"],
            )
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Dry run complete" in result.output
