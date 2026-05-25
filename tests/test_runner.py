from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from reconflow.core.runner import run_command
from reconflow.models.tool_result import ToolRunResult


def test_run_command_python_version() -> None:
    result = run_command("python", [sys.executable, "--version"])

    combined_output = f"{result.stdout}{result.stderr}"
    assert isinstance(result, ToolRunResult)
    assert result.tool_name == "python"
    assert result.command == [sys.executable, "--version"]
    assert result.exit_code == 0
    assert "Python" in combined_output
    assert result.start_time
    assert result.end_time
    assert result.duration_seconds >= 0
    assert result.timed_out is False


def test_run_command_invalid_command() -> None:
    result = run_command("missing", ["reconflow-command-that-does-not-exist"])

    assert result.exit_code == 127
    assert result.stdout == ""
    assert result.stderr
    assert result.timed_out is False


def test_run_command_timeout_behavior() -> None:
    result = run_command(
        "python",
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout=0.1,
    )

    assert result.exit_code == -1
    assert result.timed_out is True
    assert result.duration_seconds < 2


def test_run_command_writes_output_files() -> None:
    with TemporaryDirectory() as tmp_dir:
        stdout_path = Path(tmp_dir) / "stdout.txt"
        stderr_path = Path(tmp_dir) / "stderr.txt"

        result = run_command(
            "python",
            [
                sys.executable,
                "-c",
                "import sys; print('hello'); print('error', file=sys.stderr)",
            ],
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )

        assert result.exit_code == 0
        assert result.stdout_path == str(stdout_path)
        assert result.stderr_path == str(stderr_path)
        assert stdout_path.read_text(encoding="utf-8").strip() == "hello"
        assert stderr_path.read_text(encoding="utf-8").strip() == "error"
