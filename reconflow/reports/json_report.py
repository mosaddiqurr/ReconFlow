"""Report context building and JSON report generation."""

import json
import shutil
from pathlib import Path
from typing import Any

from reconflow.core.storage import read_scan_metadata, write_scan_metadata
from reconflow.reports.html import render_html_report
from reconflow.reports.markdown import render_markdown_report


VALID_REPORT_VIEWS = ("raw", "summary")
REPORT_FORMATS = {
    "markdown": "report.md",
    "html": "report.html",
    "json": "report.json",
}
VIEW_REPORT_FORMATS = {
    "raw": {
        "markdown": "report_raw.md",
        "html": "report_raw.html",
        "json": "report_raw.json",
    },
    "summary": {
        "markdown": "report_summary.md",
        "html": "report_summary.html",
        "json": "report_summary.json",
    },
}
TOOL_ARTIFACTS = {
    "subfinder": {
        "raw": "raw/subfinder.txt",
        "parsed": "parsed/subdomains.json",
        "result_key": "subdomains",
    },
    "dnsx": {
        "raw": "raw/dnsx.jsonl",
        "parsed": "parsed/assets.json",
        "result_key": "assets",
    },
    "nmap": {
        "raw": "raw/nmap.xml",
        "parsed": "parsed/services.json",
        "result_key": "services",
    },
    "httpx": {
        "raw": "raw/httpx.jsonl",
        "parsed": "parsed/live_hosts.json",
        "result_key": "live_hosts",
    },
    "whatweb": {
        "raw": "raw/whatweb.json",
        "parsed": "parsed/technologies.json",
        "result_key": "technologies",
    },
    "feroxbuster": {
        "raw": "raw/feroxbuster.json",
        "parsed": "parsed/endpoints.json",
        "result_key": "endpoints",
    },
    "katana": {
        "raw": "raw/katana.jsonl",
        "parsed": "parsed/crawled_urls.json",
        "result_key": "crawled_urls",
    },
    "nuclei": {
        "raw": "raw/nuclei.jsonl",
        "parsed": "parsed/vulnerabilities.json",
        "result_key": "vulnerabilities",
    },
    "gowitness": {
        "raw": "screenshots/",
        "parsed": "parsed/screenshots.json",
        "result_key": "screenshots",
    },
}
SUMMARY_TECHNOLOGY_KEYWORDS = {
    "apache",
    "cloudflare",
    "django",
    "express",
    "jquery",
    "laravel",
    "nginx",
    "openssl",
    "php",
    "rails",
    "react",
    "tomcat",
    "wordpress",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}


def has_parsed_data(scan_folder: str | Path) -> bool:
    """Return whether a scan has parsed JSON artifacts to report on."""
    parsed_dir = Path(scan_folder) / "parsed"
    return parsed_dir.exists() and any(parsed_dir.glob("*.json"))


def build_raw_report_context(scan_folder: str | Path) -> dict[str, Any]:
    """Build a tool-by-tool raw report context from parsed artifacts."""
    scan_path = Path(scan_folder)
    metadata = read_scan_metadata(scan_path / "metadata.json")
    parsed = _load_parsed_artifacts(scan_path)
    findings, overall_risk_score = _load_findings(metadata, parsed["findings_payload"])
    planned_tools = metadata.get("tools_planned", [])
    tool_results = [
        _build_tool_result(scan_path, metadata, parsed, tool_name, index)
        for index, tool_name in enumerate(planned_tools, start=1)
    ]

    return {
        "view": "raw",
        "scan_id": metadata.get("scan_id", scan_path.name),
        "metadata": metadata,
        "scan_overview": _scan_overview(metadata, overall_risk_score),
        "tool_results": tool_results,
        "correlated_findings": findings,
        "overall_risk_score": overall_risk_score,
        "risk_level": _risk_level(overall_risk_score),
        "report_paths": _report_paths(scan_path),
    }


def build_summary_report_context(scan_folder: str | Path) -> dict[str, Any]:
    """Build a concise executive-style report context from parsed artifacts."""
    scan_path = Path(scan_folder)
    metadata = read_scan_metadata(scan_path / "metadata.json")
    parsed = _load_parsed_artifacts(scan_path)
    findings, overall_risk_score = _load_findings(metadata, parsed["findings_payload"])
    relevant_technologies = _security_relevant_technologies(parsed["technologies"])
    vulnerability_summary = _vulnerability_summary(parsed["vulnerabilities"])
    security_observations = _security_observations(
        parsed,
        relevant_technologies,
        findings,
    )
    tool_execution_summary = _tool_execution_summary(metadata)
    recommended_actions = _recommended_actions(
        parsed,
        relevant_technologies,
        findings,
        tool_execution_summary,
    )

    return {
        "view": "summary",
        "scan_id": metadata.get("scan_id", scan_path.name),
        "scan_overview": _scan_overview(metadata, overall_risk_score),
        "key_findings": _key_findings(parsed, findings),
        "security_observations": security_observations,
        "vulnerability_summary": vulnerability_summary,
        "correlated_findings": _summary_correlated_findings(findings),
        "recommended_actions": recommended_actions,
        "tool_execution_summary": tool_execution_summary,
        "report_paths": _report_paths(scan_path),
    }


def build_report_context(scan_folder: str | Path) -> dict[str, Any]:
    """Backward-compatible report context builder; returns the summary context."""
    return build_summary_report_context(scan_folder)


def generate_report(
    scan_folder: str | Path,
    report_format: str,
    view: str = "summary",
) -> Path:
    """Generate one report format for a scan and view."""
    normalized_format = _normalize_format(report_format)
    normalized_view = _normalize_view(view)
    scan_path = Path(scan_folder)
    context = _context_for_view(scan_path, normalized_view)
    output_path = scan_path / "reports" / VIEW_REPORT_FORMATS[normalized_view][
        normalized_format
    ]

    if normalized_format == "markdown":
        render_markdown_report(
            context["scan_id"],
            output_path,
            context,
            template_name=f"report_{normalized_view}.md.j2",
        )
    elif normalized_format == "html":
        render_html_report(
            context["scan_id"],
            output_path,
            context,
            template_name=f"report_{normalized_view}.html.j2",
        )
    else:
        render_json_report(output_path, build_json_report_payload(context))

    if normalized_view == "summary":
        _write_backward_compatible_report(scan_path, normalized_format, output_path)

    return output_path


def generate_reports(
    scan_folder: str | Path,
    report_format: str = "all",
    view: str = "summary",
) -> dict[str, Path]:
    """Generate one or all report formats for a selected view."""
    normalized_view = _normalize_view(view)
    normalized_format = report_format.lower()
    formats = list(REPORT_FORMATS) if normalized_format == "all" else [
        _normalize_format(normalized_format)
    ]
    generated = {
        item: generate_report(scan_folder, item, normalized_view) for item in formats
    }
    _record_generated_reports(scan_folder, generated, normalized_view)
    return generated


def generate_all_report_views(scan_folder: str | Path) -> dict[str, dict[str, Path]]:
    """Generate raw and summary report sets for a completed scan."""
    return {
        "raw": generate_reports(scan_folder, "all", view="raw"),
        "summary": generate_reports(scan_folder, "all", view="summary"),
    }


def build_json_report_payload(context: dict[str, Any]) -> dict[str, Any]:
    """Build the structured JSON report payload for a context."""
    if context.get("view") == "raw":
        return {
            "view": "raw",
            "scan_id": context["scan_id"],
            "scan_overview": context["scan_overview"],
            "tool_results": context["tool_results"],
            "correlated_findings": context["correlated_findings"],
            "overall_risk_score": context["overall_risk_score"],
            "report_paths": context["report_paths"],
        }
    return {
        "view": "summary",
        "scan_id": context["scan_id"],
        "scan_overview": context["scan_overview"],
        "key_findings": context["key_findings"],
        "security_observations": context["security_observations"],
        "vulnerability_summary": context["vulnerability_summary"],
        "correlated_findings": context["correlated_findings"],
        "recommended_actions": context["recommended_actions"],
        "tool_execution_summary": context["tool_execution_summary"],
        "report_paths": context["report_paths"],
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


def _context_for_view(scan_path: Path, view: str) -> dict[str, Any]:
    if view == "raw":
        return build_raw_report_context(scan_path)
    return build_summary_report_context(scan_path)


def _normalize_format(report_format: str) -> str:
    normalized_format = report_format.lower()
    if normalized_format not in REPORT_FORMATS:
        valid_formats = ", ".join([*REPORT_FORMATS, "all"])
        raise ValueError(
            f"Invalid report format '{report_format}'. Valid: {valid_formats}."
        )
    return normalized_format


def _normalize_view(view: str) -> str:
    normalized_view = view.lower()
    if normalized_view not in VALID_REPORT_VIEWS:
        valid_views = ", ".join(VALID_REPORT_VIEWS)
        raise ValueError(f"Invalid report view '{view}'. Valid: {valid_views}.")
    return normalized_view


def _load_parsed_artifacts(scan_path: Path) -> dict[str, Any]:
    parsed_path = scan_path / "parsed"
    return {
        "subdomains": _read_json(parsed_path / "subdomains.json", []),
        "assets": _read_json(parsed_path / "assets.json", []),
        "live_hosts": _read_json(parsed_path / "live_hosts.json", []),
        "services": _read_json(parsed_path / "services.json", []),
        "technologies": _read_json(parsed_path / "technologies.json", []),
        "endpoints": _read_json(parsed_path / "endpoints.json", []),
        "crawled_urls": _read_json(parsed_path / "crawled_urls.json", []),
        "vulnerabilities": _read_json(parsed_path / "vulnerabilities.json", []),
        "screenshots": _read_json(parsed_path / "screenshots.json", []),
        "findings_payload": _read_json(
            parsed_path / "findings.json",
            {"overall_risk_score": 0, "findings": []},
        ),
    }


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _load_findings(
    metadata: dict[str, Any],
    findings_payload: Any,
) -> tuple[list[dict[str, Any]], int]:
    if isinstance(findings_payload, list):
        findings = findings_payload
        overall_risk_score = metadata.get("overall_risk_score", 0)
    else:
        findings = findings_payload.get("findings", [])
        overall_risk_score = findings_payload.get(
            "overall_risk_score",
            metadata.get("overall_risk_score", 0),
        )

    sorted_findings = sorted(
        findings,
        key=lambda item: int(item.get("risk_score", 0)),
        reverse=True,
    )
    return sorted_findings, int(overall_risk_score or 0)


def _scan_overview(metadata: dict[str, Any], overall_risk_score: int) -> dict[str, Any]:
    return {
        "target": metadata.get("target", "-"),
        "target_type": metadata.get("target_type", "-"),
        "scan_mode": metadata.get("mode", "-"),
        "scan_time": metadata.get("start_time", "-"),
        "overall_risk_score": overall_risk_score,
        "risk_level": _risk_level(overall_risk_score),
    }


def _risk_level(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _build_tool_result(
    scan_path: Path,
    metadata: dict[str, Any],
    parsed: dict[str, Any],
    tool_name: str,
    index: int,
) -> dict[str, Any]:
    artifacts = TOOL_ARTIFACTS.get(tool_name, {})
    result_key = artifacts.get("result_key", "")
    results = parsed.get(result_key, [])
    status, reason = _tool_status_and_reason(metadata, tool_name)
    decision = metadata.get("tool_decisions", {}).get(tool_name, {})
    why = decision.get("reason") or reason
    if status in {"skipped", "missing", "failed", "timed out"}:
        why = decision.get("skip_reason") or reason or why
    raw_path = _artifact_path(scan_path, artifacts.get("raw", ""))
    parsed_path = _artifact_path(scan_path, artifacts.get("parsed", ""))
    return {
        "index": index,
        "tool": tool_name,
        "status": status,
        "why": why or "-",
        "command_summary": _tool_command_summary(metadata, tool_name),
        "raw_output_path": str(raw_path) if raw_path else "-",
        "parsed_output_path": str(parsed_path) if parsed_path else "-",
        "raw_output_exists": raw_path.exists() if raw_path else False,
        "parsed_output_exists": parsed_path.exists() if parsed_path else False,
        "result_type": result_key,
        "results": results,
        "result_count": len(results) if isinstance(results, list) else 0,
        "vulnerabilities_by_severity": _group_by_severity(results)
        if result_key == "vulnerabilities"
        else {},
        "interesting_urls": [
            item for item in results if item.get("interesting")
        ]
        if result_key in {"endpoints", "crawled_urls"}
        else [],
    }


def _artifact_path(scan_path: Path, relative_path: str) -> Path:
    if not relative_path:
        return Path()
    return scan_path / relative_path


def _tool_status_and_reason(
    metadata: dict[str, Any],
    tool_name: str,
) -> tuple[str, str]:
    skipped = {
        item.get("tool"): item.get("reason", "")
        for item in metadata.get("tools_skipped", [])
        if isinstance(item, dict)
    }
    failed = {
        item.get("tool"): item.get("reason", "")
        for item in metadata.get("tools_failed", [])
        if isinstance(item, dict)
    }
    if tool_name in metadata.get("tools_completed", []):
        return "completed", "Tool completed successfully."
    if skipped.get(tool_name) == "Missing external tool":
        return "missing", skipped[tool_name]
    if tool_name in skipped:
        return "skipped", skipped[tool_name]
    if failed.get(tool_name) == "Command timed out":
        return "timed out", failed[tool_name]
    if tool_name in failed:
        return "failed", failed[tool_name]
    return "skipped", "Tool did not run or did not produce parsed results."


def _tool_command_summary(metadata: dict[str, Any], tool_name: str) -> str:
    for run in reversed(metadata.get("tool_runs", [])):
        if run.get("tool") == tool_name:
            return run.get("command", "-")
    return "-"


def _key_findings(
    parsed: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    vulnerabilities = parsed["vulnerabilities"]
    items: list[str] = []
    services = parsed["services"]
    live_hosts = parsed["live_hosts"]
    endpoints = parsed["endpoints"]
    if services:
        if len(services) == 1:
            items.append("1 open service was discovered.")
        else:
            items.append(f"{len(services)} open services were discovered.")
    if live_hosts:
        if len(live_hosts) == 1:
            items.append("1 live web application was detected.")
        else:
            items.append(f"{len(live_hosts)} live web applications were detected.")
    if endpoints:
        if len(endpoints) == 1:
            items.append("1 endpoint was discovered.")
        else:
            items.append(f"{len(endpoints)} endpoints were discovered.")
    if vulnerabilities:
        severity_counts = _severity_counts(vulnerabilities)
        for severity in SEVERITY_ORDER:
            count = severity_counts.get(severity, 0)
            if count:
                label = SEVERITY_LABELS[severity].lower()
                items.append(f"{count} {label} severity findings require review.")
    if findings:
        items.append(f"{len(findings)} correlated risk findings were generated.")

    return {
        "open_service_count": len(services),
        "live_web_service_count": len(live_hosts),
        "endpoint_count": len(endpoints),
        "vulnerability_count": len(vulnerabilities),
        "correlated_finding_count": len(findings),
        "items": items,
    }


def _security_observations(
    parsed: dict[str, Any],
    relevant_technologies: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, str]]:
    observations: list[dict[str, str]] = []
    for service in parsed["services"]:
        observations.append(
            {
                "type": "Exposed service",
                "title": f"{service.get('protocol', 'tcp')}/{service.get('port')}",
                "detail": (
                    f"{service.get('host', '-')} exposes "
                    f"{service.get('service_name') or 'an open service'}"
                    f"{_suffix(service.get('product'))}."
                ),
            }
        )
    for technology in relevant_technologies:
        observations.append(
            {
                "type": "Technology",
                "title": technology.get("name", "-"),
                "detail": (
                    f"{technology.get('host', '-')} fingerprints as "
                    f"{technology.get('name', '-')}"
                    f"{_suffix(technology.get('version'))}."
                ),
            }
        )
    for endpoint in parsed["endpoints"]:
        if not endpoint.get("interesting"):
            continue
        observations.append(
            {
                "type": "Interesting endpoint",
                "title": endpoint.get("path", endpoint.get("url", "-")),
                "detail": (
                    f"{endpoint.get('url', '-')} returned "
                    f"HTTP {endpoint.get('status_code', '-')}"
                ),
            }
        )
    for vulnerability in parsed["vulnerabilities"]:
        observations.append(
            {
                "type": "Vulnerability",
                "title": vulnerability.get("name", "-"),
                "detail": (
                    f"{_severity_label(vulnerability.get('severity'))}: "
                    f"{vulnerability.get('matched_url') or vulnerability.get('host', '-')}"
                ),
            }
        )
    for finding in findings:
        observations.append(
            {
                "type": "Correlated finding",
                "title": finding.get("title", "-"),
                "detail": (
                    f"{_severity_label(finding.get('severity'))} risk on "
                    f"{finding.get('affected_url') or finding.get('affected_host', '-')}"
                ),
            }
        )
    return observations


def _security_relevant_technologies(
    technologies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    relevant: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for technology in technologies:
        host = str(technology.get("host", "")).strip()
        name = str(technology.get("name", "")).strip()
        version = str(technology.get("version") or "").strip()
        normalized_name = name.lower()
        if not host or not name:
            continue
        is_relevant = (
            normalized_name in SUMMARY_TECHNOLOGY_KEYWORDS
            or any(keyword in normalized_name for keyword in SUMMARY_TECHNOLOGY_KEYWORDS)
            or bool(version)
        )
        key = (host, normalized_name, version)
        if is_relevant and key not in seen:
            seen.add(key)
            relevant.append(technology)
    return relevant


def _vulnerability_summary(
    vulnerabilities: list[dict[str, Any]],
) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for vulnerability in vulnerabilities:
        severity = _normalize_severity(vulnerability.get("severity"))
        label = SEVERITY_LABELS[severity]
        grouped.setdefault(label, []).append(
            {
                "severity": label,
                "name": vulnerability.get("name", "-"),
                "affected": vulnerability.get("matched_url")
                or vulnerability.get("host", "-"),
                "reason": vulnerability.get("description")
                or vulnerability.get("template_id")
                or "Scanner-reported finding requires validation.",
                "recommended_action": "Validate the finding and remediate the affected service.",
            }
        )
    return {SEVERITY_LABELS[item]: grouped[SEVERITY_LABELS[item]] for item in SEVERITY_ORDER if SEVERITY_LABELS[item] in grouped}


def _summary_correlated_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "severity": _severity_label(finding.get("severity")),
            "title": finding.get("title", "-"),
            "affected": finding.get("affected_url") or finding.get("affected_host", "-"),
            "risk_score": finding.get("risk_score", 0),
            "explanation": _first(finding.get("evidence", []), "-"),
            "recommended_action": finding.get(
                "recommendation",
                "Review and remediate as appropriate.",
            ),
        }
        for finding in findings
    ]


def _recommended_actions(
    parsed: dict[str, Any],
    relevant_technologies: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    tool_summary: dict[str, list[str]],
) -> list[str]:
    actions: list[str] = []
    web_ports = sorted(
        {
            int(service.get("port"))
            for service in parsed["services"]
            if service.get("port") in WEB_PORTS
        }
    )
    if web_ports:
        actions.append(
            "Review exposed web services on ports "
            f"{', '.join(str(port) for port in web_ports)}."
        )
    if any(endpoint.get("interesting") for endpoint in parsed["endpoints"]):
        actions.append("Validate whether discovered endpoints should be publicly accessible.")
    if relevant_technologies:
        actions.append("Review detected technologies for outdated versions.")
    if parsed["vulnerabilities"]:
        actions.append("Validate vulnerability scanner findings and remediate confirmed issues.")
    for finding in findings:
        recommendation = str(finding.get("recommendation", "")).strip()
        if recommendation:
            actions.append(recommendation)
    if "nuclei" in tool_summary.get("missing_tools", []) and parsed["live_hosts"]:
        actions.append("Install nuclei and rerun the scan for template-based vulnerability checks.")

    deduped_actions = _dedupe_strings(actions)
    if deduped_actions:
        return deduped_actions
    return [
        (
            "No major security-relevant findings were identified from the available "
            "scan results. Consider running a deeper scan with all external tools installed."
        )
    ]


def _tool_execution_summary(metadata: dict[str, Any]) -> dict[str, list[str]]:
    skipped_entries = metadata.get("tools_skipped", [])
    failed_entries = metadata.get("tools_failed", [])
    skipped_tools = [
        item.get("tool", "-")
        for item in skipped_entries
        if item.get("reason") != "Missing external tool"
    ]
    missing_tools = [
        item.get("tool", "-")
        for item in skipped_entries
        if item.get("reason") == "Missing external tool"
    ]
    timed_out_tools = [
        item.get("tool", "-")
        for item in failed_entries
        if item.get("reason") == "Command timed out"
    ]
    failed_tools = [
        item.get("tool", "-")
        for item in failed_entries
        if item.get("reason") != "Command timed out"
    ]
    return {
        "completed_tools": metadata.get("tools_completed", []),
        "skipped_tools": skipped_tools,
        "missing_tools": missing_tools,
        "failed_tools": failed_tools,
        "timed_out_tools": timed_out_tools,
    }


def _report_paths(scan_path: Path) -> dict[str, str]:
    return {
        "raw_report": "reports/report_raw.md",
        "summary_report": "reports/report_summary.md",
        "json_report": "reports/report_summary.json",
        "raw_json_report": "reports/report_raw.json",
        "backward_markdown_report": "reports/report.md",
        "backward_html_report": "reports/report.html",
        "backward_json_report": "reports/report.json",
    }


def _write_backward_compatible_report(
    scan_path: Path,
    report_format: str,
    source_path: Path,
) -> None:
    compat_path = scan_path / "reports" / REPORT_FORMATS[report_format]
    compat_path.parent.mkdir(parents=True, exist_ok=True)
    if source_path.resolve() == compat_path.resolve():
        return
    shutil.copyfile(source_path, compat_path)


def _record_generated_reports(
    scan_folder: str | Path,
    generated: dict[str, Path],
    view: str,
) -> None:
    scan_path = Path(scan_folder)
    metadata_path = scan_path / "metadata.json"
    if not metadata_path.exists():
        return
    metadata = read_scan_metadata(metadata_path)
    reports = metadata.setdefault("reports_generated", {})
    view_reports = reports.setdefault(view, {})
    for report_format, path in generated.items():
        view_reports[report_format] = str(path)
        reports[f"{view}_{report_format}"] = str(path)
        if view == "summary":
            compat_path = scan_path / "reports" / REPORT_FORMATS[report_format]
            reports[report_format] = str(compat_path)
    write_scan_metadata(scan_path, metadata)


def _group_by_severity(items: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(items, list):
        return {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        severity = _normalize_severity(item.get("severity"))
        grouped.setdefault(SEVERITY_LABELS[severity], []).append(item)
    return {
        SEVERITY_LABELS[severity]: grouped[SEVERITY_LABELS[severity]]
        for severity in SEVERITY_ORDER
        if SEVERITY_LABELS[severity] in grouped
    }


def _severity_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for item in items:
        counts[_normalize_severity(item.get("severity"))] += 1
    return counts


def _normalize_severity(value: Any) -> str:
    normalized = str(value or "info").lower()
    if normalized in {"informational", "information"}:
        return "info"
    if normalized not in SEVERITY_ORDER:
        return "info"
    return normalized


def _severity_label(value: Any) -> str:
    return SEVERITY_LABELS[_normalize_severity(value)]


def _suffix(value: Any) -> str:
    if value is None or value == "":
        return ""
    return f" {value}"


def _first(items: Any, default: str) -> str:
    if isinstance(items, list) and items:
        return str(items[0])
    return default


def _dedupe_strings(items: list[str]) -> list[str]:
    deduped: list[str] = []
    for item in items:
        if item and item not in deduped:
            deduped.append(item)
    return deduped
