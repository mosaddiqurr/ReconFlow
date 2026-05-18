"""Correlated finding model."""

from pydantic import BaseModel, Field


class Finding(BaseModel):
    title: str
    severity: str
    risk_score: int = Field(default=0, ge=0, le=100)
    affected_host: str
    affected_url: str | None = None
    evidence: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    recommendation: str
