"""Endpoint model."""

from pydantic import BaseModel


class Endpoint(BaseModel):
    url: str
    host: str
    path: str
    status_code: int | None = None
    content_length: int | None = None
    words: int | None = None
    lines: int | None = None
    source_tool: str = "feroxbuster"
    interesting: bool = False
