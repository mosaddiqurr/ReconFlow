"""Screenshot model."""

from pydantic import BaseModel


class Screenshot(BaseModel):
    url: str
    host: str
    screenshot_path: str
    status: str
    source_tool: str = "gowitness"
