"""Scan comparison helpers for parsed ReconFlow artifacts."""

import json
from pathlib import Path
from typing import Any


COMPARISON_FIELDS = (
    "new_subdomains",
    "removed_subdomains",
    "new_live_hosts",
    "removed_live_hosts",
    "new_open_ports",
    "closed_ports",
    "new_technologies",
    "removed_technologies",
    "new_endpoints",
    "removed_endpoints",
    "new_vulnerabilities",
    "resolved_vulnerabilities",
    "new_correlated_findings",
    "resolved_correlated_findings",
)


def compare_scans(
    scan_1_folder: str | Path,
    scan_2_folder: str | Path,
    scan_id_1: str,
    scan_id_2: str,
    output_base_dir: str | Path = "scans",
) -> dict[str, Any]:
    """Compare parsed JSON artifacts from two scan folders and save the result."""
    baseline = load_comparison_artifacts(scan_1_folder)
    current = load_comparison_artifacts(scan_2_folder)

    comparison = {
        "scan_id_1": scan_id_1,
        "scan_id_2": scan_id_2,
        "comparison_direction": f"{scan_id_1} -> {scan_id_2}",
        "new_subdomains": _added(baseline["subdomains"], current["subdomains"]),
        "removed_subdomains": _removed(baseline["subdomains"], current["subdomains"]),
        "new_live_hosts": _added(baseline["live_hosts"], current["live_hosts"]),
        "removed_live_hosts": _removed(baseline["live_hosts"], current["live_hosts"]),
        "new_open_ports": _added(baseline["open_ports"], current["open_ports"]),
        "closed_ports": _removed(baseline["open_ports"], current["open_ports"]),
        "new_technologies": _added(
            baseline["technologies"],
            current["technologies"],
        ),
        "removed_technologies": _removed(
            baseline["technologies"],
            current["technologies"],
        ),
        "new_endpoints": _added(baseline["endpoints"], current["endpoints"]),
        "removed_endpoints": _removed(baseline["endpoints"], current["endpoints"]),
        "new_vulnerabilities": _added(
            baseline["vulnerabilities"],
            current["vulnerabilities"],
        ),
        "resolved_vulnerabilities": _removed(
            baseline["vulnerabilities"],
            current["vulnerabilities"],
        ),
        "new_correlated_findings": _added(
            baseline["correlated_findings"],
            current["correlated_findings"],
        ),
        "resolved_correlated_findings": _removed(
            baseline["correlated_findings"],
            current["correlated_findings"],
        ),
    }
    output_path = save_comparison_json(comparison, scan_id_1, scan_id_2, output_base_dir)
    comparison["output_path"] = str(output_path)
    return comparison


def load_comparison_artifacts(scan_folder: str | Path) -> dict[str, list[str]]:
    """Load comparable parsed artifact IDs from a scan folder."""
    parsed_dir = Path(scan_folder) / "parsed"
    return {
        "subdomains": _subdomains(parsed_dir / "subdomains.json"),
        "live_hosts": _live_hosts(parsed_dir / "live_hosts.json"),
        "open_ports": _open_ports(parsed_dir / "services.json"),
        "technologies": _technologies(parsed_dir / "technologies.json"),
        "endpoints": _endpoints(parsed_dir / "endpoints.json"),
        "vulnerabilities": _vulnerabilities(parsed_dir / "vulnerabilities.json"),
        "correlated_findings": _correlated_findings(parsed_dir / "findings.json"),
    }


def save_comparison_json(
    comparison: dict[str, Any],
    scan_id_1: str,
    scan_id_2: str,
    output_base_dir: str | Path = "scans",
) -> Path:
    """Save comparison output under scans/comparisons."""
    output_dir = Path(output_base_dir) / "comparisons"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{scan_id_1}_vs_{scan_id_2}.json"
    payload = dict(comparison)
    payload["output_path"] = str(output_path)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return output_path


def _added(baseline: list[str], current: list[str]) -> list[str]:
    return sorted(set(current) - set(baseline))


def _removed(baseline: list[str], current: list[str]) -> list[str]:
    return sorted(set(baseline) - set(current))


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _subdomains(path: Path) -> list[str]:
    payload = _read_json(path, [])
    return sorted({str(item).lower() for item in payload if item})


def _live_hosts(path: Path) -> list[str]:
    payload = _read_json(path, [])
    return sorted(
        {
            str(item.get("url") or item.get("host") or "").lower()
            for item in payload
            if item.get("url") or item.get("host")
        }
    )


def _open_ports(path: Path) -> list[str]:
    payload = _read_json(path, [])
    ports = set()
    for item in payload:
        host = str(item.get("host", "")).lower()
        port = item.get("port")
        protocol = str(item.get("protocol") or "tcp").lower()
        service_name = str(item.get("service_name") or "").lower()
        if host and port is not None:
            ports.add(f"{host}:{port}/{protocol} {service_name}".strip())
    return sorted(ports)


def _technologies(path: Path) -> list[str]:
    payload = _read_json(path, [])
    technologies = set()
    for item in payload:
        host = str(item.get("host") or "").lower()
        name = str(item.get("name") or "").lower()
        version = str(item.get("version") or "").lower()
        if host and name:
            value = f"{host} {name}"
            if version:
                value = f"{value} {version}"
            technologies.add(value)
    return sorted(technologies)


def _endpoints(path: Path) -> list[str]:
    payload = _read_json(path, [])
    return sorted(
        {
            str(item.get("url") or "").lower()
            for item in payload
            if item.get("url")
        }
    )


def _vulnerabilities(path: Path) -> list[str]:
    payload = _read_json(path, [])
    vulnerabilities = set()
    for item in payload:
        template_id = str(item.get("template_id") or "").lower()
        severity = str(item.get("severity") or "").lower()
        matched_url = str(item.get("matched_url") or item.get("host") or "").lower()
        name = str(item.get("name") or "").lower()
        value = "|".join(part for part in (template_id, severity, matched_url, name) if part)
        if value:
            vulnerabilities.add(value)
    return sorted(vulnerabilities)


def _correlated_findings(path: Path) -> list[str]:
    payload = _read_json(path, {"findings": []})
    findings = payload.get("findings", payload) if isinstance(payload, dict) else payload
    values = set()
    for item in findings:
        title = str(item.get("title") or "").lower()
        host = str(item.get("affected_host") or "").lower()
        url = str(item.get("affected_url") or "").lower()
        severity = str(item.get("severity") or "").lower()
        value = "|".join(part for part in (title, severity, host, url) if part)
        if value:
            values.add(value)
    return sorted(values)
