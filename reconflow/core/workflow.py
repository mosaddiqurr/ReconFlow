"""Workflow definitions and step metadata."""

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkflowStep:
    name: str
    description: str


TOOL_DESCRIPTIONS = {
    "nmap": "Network and service discovery",
    "subfinder": "Passive subdomain discovery",
    "dnsx": "DNS probing and resolution",
    "httpx": "HTTP probing and web metadata collection",
    "whatweb": "Web technology fingerprinting",
    "feroxbuster": "Content and directory discovery",
    "katana": "Web crawling and URL discovery",
    "nuclei": "Template-based vulnerability checks",
    "gowitness": "Website screenshot capture",
}

WORKFLOW_DEFINITIONS: dict[str, tuple[str, ...]] = {
    "quick": ("nmap", "httpx"),
    "standard": (
        "subfinder",
        "dnsx",
        "nmap",
        "httpx",
        "whatweb",
        "feroxbuster",
        "nuclei",
    ),
    "deep": (
        "subfinder",
        "dnsx",
        "nmap",
        "httpx",
        "whatweb",
        "feroxbuster",
        "katana",
        "nuclei",
        "gowitness",
    ),
}
VALID_SCAN_MODES = tuple(WORKFLOW_DEFINITIONS)
DEFAULT_SCAN_MODE = "standard"


def get_workflow_steps(
    mode: str,
    enabled_tools: list[str] | tuple[str, ...] | None = None,
) -> list[WorkflowStep]:
    """Return ordered workflow steps for a supported scan mode."""
    normalized_mode = mode.lower()
    if normalized_mode not in WORKFLOW_DEFINITIONS:
        valid_modes = ", ".join(VALID_SCAN_MODES)
        raise ValueError(f"Invalid scan mode '{mode}'. Valid modes: {valid_modes}.")

    enabled_tool_set = set(enabled_tools) if enabled_tools is not None else None
    workflow_tools = WORKFLOW_DEFINITIONS[normalized_mode]
    return [
        WorkflowStep(tool_name, TOOL_DESCRIPTIONS[tool_name])
        for tool_name in workflow_tools
        if enabled_tool_set is None or tool_name in enabled_tool_set
    ]
