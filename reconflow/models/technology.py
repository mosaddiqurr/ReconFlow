"""Technology model."""

from pydantic import BaseModel


class Technology(BaseModel):
    host: str
    url: str
    name: str
    version: str | None = None
    category: str | None = None
    source_tool: str = "whatweb"
