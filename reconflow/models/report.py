"""Report model."""

from pydantic import BaseModel


class Report(BaseModel):
    scan_id: str
    generated_at: str
    format: str
