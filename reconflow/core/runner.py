"""Execution runner helpers."""

from pathlib import Path
import subprocess
from time import perf_counter

from rich.console import Console

from reconflow.models.tool_result import ToolRunResult
from reconflow.utils.time_utils import utc_now_iso

console = Console()


def _coerce_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _write_output(path: str | Path | None, content: str) -> str | None:
    if path is None:
        return None

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return str(output_path)


def run_command(
    tool_name: str,
    command: list[str],
    timeout: float | None = None,
    stdout_path: str | Path | None = None,
    stderr_path: str | Path | None = None,
) -> ToolRunResult:
    """Run a command safely and return a structured result."""
    if not isinstance(command, list):
        raise TypeError("command must be provided as a list of arguments")

    start_time = utc_now_iso()
    start_counter = perf_counter()
    stdout = ""
    stderr = ""
    exit_code = 0
    timed_out = False

    try:
        completed_process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = completed_process.stdout
        stderr = completed_process.stderr
        exit_code = completed_process.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = _coerce_timeout_output(exc.stdout)
        stderr = _coerce_timeout_output(exc.stderr)
        exit_code = -1
        timed_out = True
    except FileNotFoundError as exc:
        stderr = str(exc)
        exit_code = 127

    end_time = utc_now_iso()
    duration_seconds = round(perf_counter() - start_counter, 6)
    written_stdout_path = _write_output(stdout_path, stdout)
    written_stderr_path = _write_output(stderr_path, stderr)

    return ToolRunResult(
        tool_name=tool_name,
        command=command,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration_seconds,
        timed_out=timed_out,
        stdout_path=written_stdout_path,
        stderr_path=written_stderr_path,
    )


class Runner:
    """Runs workflow steps in order.

    Real execution logic will be added later.
    """

    def run(self, steps: list[str]) -> None:
        for step in steps:
            console.print(f"[yellow]placeholder[/yellow] running step: {step}")
