"""Tool execution result model."""

from pydantic import BaseModel


class ToolRunResult(BaseModel):
    tool_name: str
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    start_time: str
    end_time: str
    duration_seconds: float
    timed_out: bool
    stdout_path: str | None = None
    stderr_path: str | None = None
