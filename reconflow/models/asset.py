"""Asset model."""

from pydantic import BaseModel


class Asset(BaseModel):
    hostname: str
    ip: str | None = None
    record_type: str | None = None
    source_tool: str = "dnsx"
    is_resolved: bool = False
