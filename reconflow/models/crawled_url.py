"""Crawled URL model."""

from pydantic import BaseModel, Field


class CrawledUrl(BaseModel):
    url: str
    host: str
    path: str
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    source_tool: str = "katana"
