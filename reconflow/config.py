"""Configuration loading helpers."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from reconflow.core.workflow import DEFAULT_SCAN_MODE, VALID_SCAN_MODES
from reconflow.exceptions import ConfigurationError


DEFAULT_ENABLED_TOOLS = [
    "nmap",
    "subfinder",
    "dnsx",
    "httpx",
    "whatweb",
    "feroxbuster",
    "katana",
    "nuclei",
    "gowitness",
]


class SafeDefaults(BaseModel):
    authorization_required: bool = True
    run_external_tools: bool = False
    create_outputs: bool = True


class ReconFlowConfig(BaseModel):
    default_mode: str = DEFAULT_SCAN_MODE
    output_directory: str = "scans"
    wordlist_path: str = "reconflow/data/wordlists/common.txt"
    enabled_tools: list[str] = Field(default_factory=lambda: DEFAULT_ENABLED_TOOLS.copy())
    tool_timeouts: dict[str, int] = Field(
        default_factory=lambda: {tool_name: 60 for tool_name in DEFAULT_ENABLED_TOOLS}
    )
    safe_defaults: SafeDefaults = Field(default_factory=SafeDefaults)

    @field_validator("default_mode")
    @classmethod
    def validate_default_mode(cls, value: str) -> str:
        normalized_value = value.lower()
        if normalized_value not in VALID_SCAN_MODES:
            valid_modes = ", ".join(VALID_SCAN_MODES)
            raise ValueError(f"default_mode must be one of: {valid_modes}")
        return normalized_value


def load_config(config_path: str | Path | None = None) -> ReconFlowConfig:
    """Load YAML config into a validated Pydantic model."""
    if config_path is None:
        return ReconFlowConfig()

    path = Path(config_path)
    if not path.exists():
        raise ConfigurationError(f"Config file not found: {path}")

    try:
        data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Failed to parse YAML config: {exc}") from exc

    return ReconFlowConfig.model_validate(data)
