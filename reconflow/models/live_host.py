"""Live web host model."""

from pydantic import BaseModel, Field


class LiveHost(BaseModel):
    url: str
    host: str
    status_code: int | None = None
    title: str = ""
    webserver: str = ""
    content_length: int | None = None
    technologies: list[str] = Field(default_factory=list)
    source_tool: str = "httpx"
