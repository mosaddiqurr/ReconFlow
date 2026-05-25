"""Nmap integration."""

import json
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Any

from reconflow.core.runner import run_command
from reconflow.models.service import Service

from reconflow.tools.base import ToolAdapter


ADDRESS_RECORD_TYPES = {"A", "AAAA"}


def select_nmap_targets(
    target: str,
    assets: list[Any] | None = None,
    resolved_hosts: list[str] | None = None,
) -> list[str]:
    """Select deduplicated Nmap targets, preferring A/AAAA IPs from dnsx."""
    ip_targets: list[str] = []
    hostname_targets: list[str] = []

    for asset in assets or []:
        record_type = str(_asset_value(asset, "record_type") or "").upper()
        hostname = str(_asset_value(asset, "hostname") or "").strip()
        ip = str(_asset_value(asset, "ip") or "").strip()
        is_resolved = bool(_asset_value(asset, "is_resolved"))

        if record_type in ADDRESS_RECORD_TYPES and ip:
            ip_targets.append(ip)
        elif is_resolved and record_type != "CNAME" and hostname:
            hostname_targets.append(hostname)

    if ip_targets:
        return _dedupe_preserving_order(ip_targets)

    if hostname_targets:
        return _dedupe_preserving_order(hostname_targets)

    if resolved_hosts:
        return _dedupe_preserving_order(resolved_hosts)

    return [target]


def _asset_value(asset: Any, field_name: str) -> Any:
    if isinstance(asset, dict):
        return asset.get(field_name)
    return getattr(asset, field_name, None)


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized_value = value.strip()
        if not normalized_value or normalized_value in seen:
            continue
        seen.add(normalized_value)
        deduped.append(normalized_value)
    return deduped


def build_nmap_command(
    target: str | list[str],
    output_xml_path: str | Path,
) -> list[str]:
    """Build the safe baseline Nmap service-detection command."""
    targets = target if isinstance(target, list) else [target]
    return ["nmap", "-sV", "-oX", str(output_xml_path), *targets]


def parse_nmap_xml(xml_path: str | Path) -> list[Service]:
    """Parse Nmap XML output into service models."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    services: list[Service] = []

    for host_node in root.findall("host"):
        address_node = host_node.find("address")
        host = address_node.get("addr", "") if address_node is not None else ""

        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            state = state_node.get("state", "") if state_node is not None else ""

            if state != "open":
                continue

            services.append(
                Service(
                    host=host,
                    port=int(port_node.get("portid", "0")),
                    protocol=port_node.get("protocol", "tcp"),
                    service_name=(
                        service_node.get("name", "") if service_node is not None else ""
                    ),
                    product=(
                        service_node.get("product", "") if service_node is not None else ""
                    ),
                    version=(
                        service_node.get("version", "") if service_node is not None else ""
                    ),
                    state=state,
                    source_tool="nmap",
                )
            )

    return services


def save_services_json(services: list[Service], output_path: str | Path) -> Path:
    """Save parsed service models as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [service.model_dump() for service in services]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def run_nmap(
    target: str | list[str],
    scan_folder: str | Path,
    timeout: float | None = None,
):
    """Run Nmap for a scan folder using the shared command runner."""
    scan_path = Path(scan_folder)
    raw_xml_path = scan_path / "raw" / "nmap.xml"
    command = build_nmap_command(target, raw_xml_path)
    return run_command("nmap", command, timeout=timeout)


class NmapTool(ToolAdapter):
    name = "nmap"

    def check_available(self) -> bool:
        from shutil import which

        return which("nmap") is not None

    def build_command(self, target: str) -> list[str]:
        return build_nmap_command(target, "nmap.xml")
