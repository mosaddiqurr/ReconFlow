"""Command utility helpers."""

from dataclasses import dataclass
import shutil


@dataclass(frozen=True)
class RequiredTool:
    """Metadata for an external command-line tool."""

    name: str
    purpose: str
    command: str
    install_note: str


@dataclass(frozen=True)
class ToolCheckResult:
    """Result of checking whether a required tool is available."""

    tool: RequiredTool
    is_installed: bool
    detected_path: str | None


REQUIRED_TOOLS: tuple[RequiredTool, ...] = (
    RequiredTool(
        name="nmap",
        purpose="Network and service discovery",
        command="nmap",
        install_note="Install from https://nmap.org/download.html or your package manager.",
    ),
    RequiredTool(
        name="subfinder",
        purpose="Passive subdomain discovery",
        command="subfinder",
        install_note="Install via ProjectDiscovery: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest.",
    ),
    RequiredTool(
        name="dnsx",
        purpose="DNS probing and resolution",
        command="dnsx",
        install_note="Install via ProjectDiscovery: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest.",
    ),
    RequiredTool(
        name="httpx",
        purpose="HTTP probing and web metadata collection",
        command="httpx",
        install_note="Install via ProjectDiscovery: go install github.com/projectdiscovery/httpx/cmd/httpx@latest.",
    ),
    RequiredTool(
        name="whatweb",
        purpose="Web technology fingerprinting",
        command="whatweb",
        install_note="Install from https://github.com/urbanadventurer/WhatWeb or your package manager.",
    ),
    RequiredTool(
        name="feroxbuster",
        purpose="Content and directory discovery",
        command="feroxbuster",
        install_note="Install from https://github.com/epi052/feroxbuster/releases or your package manager.",
    ),
    RequiredTool(
        name="katana",
        purpose="Web crawling and URL discovery",
        command="katana",
        install_note="Install via ProjectDiscovery: go install github.com/projectdiscovery/katana/cmd/katana@latest.",
    ),
    RequiredTool(
        name="nuclei",
        purpose="Template-based vulnerability checks",
        command="nuclei",
        install_note="Install via ProjectDiscovery: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest.",
    ),
    RequiredTool(
        name="gowitness",
        purpose="Website screenshot capture",
        command="gowitness",
        install_note="Install from https://github.com/sensepost/gowitness/releases or your package manager.",
    ),
)


def check_command_exists(command_name: str) -> str | None:
    """Return the detected command path, or None when unavailable."""
    return shutil.which(command_name)


def check_required_tools() -> list[ToolCheckResult]:
    """Check all required external tools without running them."""
    results: list[ToolCheckResult] = []
    for tool in REQUIRED_TOOLS:
        detected_path = check_command_exists(tool.command)
        results.append(
            ToolCheckResult(
                tool=tool,
                is_installed=detected_path is not None,
                detected_path=detected_path,
            )
        )
    return results


def build_placeholder_command(tool: str, target: str) -> str:
    return f"{tool} {target}"
