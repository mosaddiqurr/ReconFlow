"""Subfinder integration."""

import json
from pathlib import Path

from reconflow.core.runner import run_command
from reconflow.core.validator import detect_target_type
from reconflow.tools.base import ToolAdapter


def select_subfinder_domain(target: str) -> str:
    """Use an apex-like domain for common www hostnames."""
    normalized_target = target.strip()
    if normalized_target.lower().startswith("www."):
        candidate = normalized_target[4:].lower()
        if detect_target_type(candidate) == "domain":
            return candidate
    return normalized_target


def build_subfinder_command(target: str, output_path: str | Path) -> list[str]:
    """Build the Subfinder command for passive subdomain discovery."""
    return ["subfinder", "-silent", "-d", target, "-o", str(output_path)]


def parse_subfinder_output(output_path: str | Path) -> list[str]:
    """Parse newline-delimited Subfinder output into unique subdomains."""
    subdomains: list[str] = []
    seen: set[str] = set()
    for line in Path(output_path).read_text(encoding="utf-8").splitlines():
        subdomain = line.strip().lower()
        if not subdomain or subdomain in seen:
            continue
        seen.add(subdomain)
        subdomains.append(subdomain)

    return subdomains


def save_subdomains_json(subdomains: list[str], output_path: str | Path) -> Path:
    """Save parsed subdomains as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(subdomains, indent=2) + "\n", encoding="utf-8")
    return path


def run_subfinder(
    target: str,
    scan_folder: str | Path,
    timeout: float | None = None,
):
    """Run Subfinder for a domain target using the shared command runner."""
    raw_output_path = Path(scan_folder) / "raw" / "subfinder.txt"
    command = build_subfinder_command(select_subfinder_domain(target), raw_output_path)
    return run_command("subfinder", command, timeout=timeout)


class SubfinderTool(ToolAdapter):
    name = "subfinder"

    def check_available(self) -> bool:
        from shutil import which

        return which("subfinder") is not None

    def build_command(self, target: str) -> list[str]:
        return build_subfinder_command(target, "subfinder.txt")
