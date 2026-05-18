"""Service model."""

from pydantic import BaseModel


class Service(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    product: str = ""
    version: str = ""
    state: str = ""
    source_tool: str = "nmap"
