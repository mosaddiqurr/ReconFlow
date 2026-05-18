"""Scan model."""

from datetime import datetime

from pydantic import BaseModel, Field


class Scan(BaseModel):
    scan_id: str
    target: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.utcnow)
