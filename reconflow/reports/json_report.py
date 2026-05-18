"""Report context building and JSON report generation."""

import json
from pathlib import Path
from typing import Any

from reconflow.core.storage import read_scan_metadata, write_scan_metadata
from reconflow.reports.html import render_html_report
from reconflow.reports.markdown import render_markdown_report


REPORT_FORMATS = {
    "markdown": "report.md",
    "html": "report.html",
    "json": "report.json",
}


def has_parsed_data(scan_folder: str | Path) -> bool:
    """Return whether a scan has parsed JSON artifacts to report on."""
    parsed_dir = Path(scan_folder) / "parsed"
    return parsed_dir.exists() and any(parsed_dir.glob("*.json"))


def build_report_context(scan_folder: str | Path) -> dict[str, Any]:
    """Build a report context from metadata and parsed JSON artifacts."""
    scan_path = Path(scan_folder)
    metadata = read_scan_metadata(scan_path / "metadata.json")
    parsed = {
        "assets": _read_json(scan_path / "parsed" / "assets.json", []),
        "live_hosts": _read_json(scan_path / "parsed" / "live_hosts.json", []),
        "services": _read_json(scan_path / "parsed" / "services.json", []),
        "technologies": _read_json(scan_path / "parsed" / "technologies.json", []),
        "endpoints": _read_json(scan_path / "parsed" / "endpoints.json", []),
        "vulnerabilities": _read_json(
            scan_path / "parsed" / "vulnerabilities.json",
            [],
        ),
        "findings_payload": _read_json(
            scan_path / "parsed" / "findings.json",
            {"overall_risk_score": 0, "findings": []},
        ),
    }
    findings_payload = parsed["findings_payload"]
    if isinstance(findings_payload, list):
        findings = findings_payload
        overall_risk_score = metadata.get("overall_risk_score", 0)
    else:
        findings = findings_payload.get("findings", [])
        overall_risk_score = findings_payload.get(
            "overall_risk_score",
            metadata.get("overall_risk_score", 0),
        )

    findings = sorted(
        findings,
        key=lambda item: int(item.get("risk_score", 0)),
        reverse=True,
    )
    interesting_endpoints = [
        endpoint for endpoint in parsed["endpoints"] if endpoint.get("interesting")
    ]
    recommended_next_steps = _recommended_next_steps(findings)

    return {
        "scan_id": metadata.get("scan_id", scan_path.name),
        "metadata": metadata,
        "target_scope": {
            "target": metadata.get("target", "-"),
            "target_type": metadata.get("target_type", "-"),
            "mode": metadata.get("mode", "-"),
            "authorization_status": "Authorized",
        },
        "tools_used": metadata.get("tools_completed", []),
        "recon_workflow": metadata.get("tools_planned", []),
        "assets": parsed["assets"],
        "live_hosts": parsed["live_hosts"],
        "services": parsed["services"],
        "technologies": parsed["technologies"],
        "interesting_endpoints": interesting_endpoints,
        "vulnerabilities": parsed["vulnerabilities"],
        "findings": findings,
        "overall_risk_score": overall_risk_score,
        "recommended_next_steps": recommended_next_steps,
        "evidence_appendix": _evidence_appendix(findings),
        "executive_summary": _executive_summary(
            metadata,
            parsed,
            findings,
            overall_risk_score,
        ),
    }


def generate_report(
    scan_folder: str | Path,
    report_format: str,
) -> Path:
    """Generate one report format for a scan."""
    normalized_format = report_format.lower()
    if normalized_format not in REPORT_FORMATS:
        valid_formats = ", ".join([*REPORT_FORMATS, "all"])
        raise ValueError(f"Invalid report format '{report_format}'. Valid: {valid_formats}.")

    scan_path = Path(scan_folder)
    context = build_report_context(scan_path)
    output_path = scan_path / "reports" / REPORT_FORMATS[normalized_format]

    if normalized_format == "markdown":
        render_markdown_report(context["scan_id"], output_path, context)
    elif normalized_format == "html":
        render_html_report(context["scan_id"], output_path, context)
    else:
        render_json_report(output_path, build_json_report_payload(context))

    return output_path


def generate_reports(
    scan_folder: str | Path,
    report_format: str = "all",
) -> dict[str, Path]:
    """Generate one or all report formats for a scan."""
    normalized_format = report_format.lower()
    formats = list(REPORT_FORMATS) if normalized_format == "all" else [normalized_format]
    generated = {item: generate_report(scan_folder, item) for item in formats}
    _record_generated_reports(scan_folder, generated)
    return generated


def build_json_report_payload(context: dict[str, Any]) -> dict[str, Any]:
    """Build the structured JSON report payload."""
    return {
        "scan_id": context["scan_id"],
        "executive_summary": context["executive_summary"],
        "target_scope": context["target_scope"],
        "tools_used": context["tools_used"],
        "recon_workflow": context["recon_workflow"],
        "discovered_assets": context["assets"],
        "live_hosts": context["live_hosts"],
        "open_ports_and_services": context["services"],
        "technologies": context["technologies"],
        "interesting_endpoints": context["interesting_endpoints"],
        "vulnerability_findings": context["vulnerabilities"],
        "prioritized_findings": context["findings"],
        "overall_risk_score": context["overall_risk_score"],
        "recommended_next_steps": context["recommended_next_steps"],
        "evidence_appendix": context["evidence_appendix"],
    }


def render_json_report(output_path: str | Path, payload: dict) -> None:
    """Write JSON report content to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def find_scan_folder(scan_id: str, base_dir: str | Path = "scans") -> Path | None:
    """Find a scan folder by scan ID."""
    base_path = Path(base_dir)
    candidate = base_path / scan_id
    if candidate.is_dir():
        return candidate
    for metadata_path in base_path.glob("scan_*/metadata.json"):
        metadata = _read_json(metadata_path, {})
        if metadata.get("scan_id") == scan_id:
            return metadata_path.parent
    return None


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _executive_summary(
    metadata: dict[str, Any],
    parsed: dict[str, Any],
    findings: list[dict[str, Any]],
    overall_risk_score: int,
) -> dict[str, Any]:
    high_priority_count = sum(
        1
        for finding in findings
        if str(finding.get("severity", "")).lower() in {"high", "critical"}
    )
    return {
        "target": metadata.get("target", "-"),
        "mode": metadata.get("mode", "-"),
        "overall_risk_score": overall_risk_score,
        "finding_count": len(findings),
        "high_priority_finding_count": high_priority_count,
        "asset_count": len(parsed["assets"]),
        "live_host_count": len(parsed["live_hosts"]),
        "service_count": len(parsed["services"]),
        "technology_count": len(parsed["technologies"]),
        "interesting_endpoint_count": sum(
            1 for endpoint in parsed["endpoints"] if endpoint.get("interesting")
        ),
        "vulnerability_count": len(parsed["vulnerabilities"]),
    }


def _recommended_next_steps(findings: list[dict[str, Any]]) -> list[str]:
    recommendations: list[str] = []
    for finding in findings:
        recommendation = str(finding.get("recommendation", "")).strip()
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)
    if recommendations:
        return recommendations
    return [
        "Review parsed reconnaissance data and validate any exposed services manually.",
        "Confirm all testing remains within the authorized target scope.",
    ]


def _evidence_appendix(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "title": finding.get("title", "-"),
            "affected_host": finding.get("affected_host", "-"),
            "affected_url": finding.get("affected_url"),
            "source_tools": finding.get("source_tools", []),
            "evidence": finding.get("evidence", []),
        }
        for finding in findings
    ]


def _record_generated_reports(
    scan_folder: str | Path,
    generated: dict[str, Path],
) -> None:
    scan_path = Path(scan_folder)
    metadata_path = scan_path / "metadata.json"
    if not metadata_path.exists():
        return
    metadata = read_scan_metadata(metadata_path)
    reports = metadata.setdefault("reports_generated", {})
    for report_format, path in generated.items():
        reports[report_format] = str(path)
    write_scan_metadata(scan_path, metadata)
