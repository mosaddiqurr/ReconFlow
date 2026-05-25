"""Typer CLI entry point for ReconFlow."""

from pathlib import Path
import shlex

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconflow.config import load_config
from reconflow.constants import APP_NAME, APP_VERSION, AUTHORIZATION_WARNING
from reconflow.core.comparator import COMPARISON_FIELDS, compare_scans
from reconflow.core.correlator import correlate_scan
from reconflow.core.orchestrator import Orchestrator, WorkflowDecision, WorkflowState
from reconflow.core.storage import create_scan_folder, read_scan_history, write_scan_metadata
from reconflow.core.workflow import get_workflow_steps
from reconflow.models.target import Target
from reconflow.reports.json_report import (
    build_raw_report_context,
    build_summary_report_context,
    find_scan_folder,
    generate_all_report_views,
    generate_reports,
    has_parsed_data,
)
from reconflow.tools.dnsx import (
    build_dnsx_command,
    parse_dnsx_jsonl,
    run_dnsx,
    save_assets_json,
)
from reconflow.tools.feroxbuster import (
    parse_feroxbuster_json,
    run_feroxbuster,
    save_endpoints_json,
)
from reconflow.tools.gowitness import (
    collect_screenshot_metadata,
    load_gowitness_targets,
    parse_gowitness_jsonl,
    run_gowitness,
    save_screenshots_json,
)
from reconflow.tools.httpx import (
    build_httpx_command,
    parse_httpx_jsonl,
    run_httpx,
    save_live_hosts_json,
    select_httpx_inputs,
)
from reconflow.tools.katana import (
    merge_interesting_crawled_urls_into_endpoints,
    parse_katana_jsonl,
    run_katana,
    save_crawled_urls_json,
)
from reconflow.tools.nmap import (
    build_nmap_command,
    parse_nmap_xml,
    run_nmap,
    save_services_json,
    select_nmap_targets,
)
from reconflow.tools.nuclei import (
    parse_nuclei_jsonl,
    run_nuclei,
    save_vulnerabilities_json,
)
from reconflow.tools.subfinder import (
    build_subfinder_command,
    parse_subfinder_output,
    run_subfinder,
    save_subdomains_json,
    select_subfinder_domain,
)
from reconflow.tools.whatweb import (
    parse_whatweb_json,
    run_whatweb,
    save_technologies_json,
)
from reconflow.utils.command_utils import check_required_tools

app = typer.Typer(
    name="reconflow",
    help="CLI reconnaissance orchestration tool (authorized testing only).",
    no_args_is_help=True,
)
tools_app = typer.Typer(help="Tool integration helpers.")
app.add_typer(tools_app, name="tools")
console = Console()
VALID_RESULT_VIEWS = ("raw", "summary")
ERROR_SUMMARY_MAX_LINES = 5
ERROR_SUMMARY_MAX_CHARS = 600
RAW_RESULT_LIMITS = {
    "subdomains": 20,
    "assets": 20,
    "services": 20,
    "live_hosts": 20,
    "technologies": 20,
    "endpoints": 20,
    "crawled_urls": 10,
    "vulnerabilities": 20,
    "screenshots": 20,
}


def _mark_tool_completed(metadata: dict, tool_name: str) -> None:
    completed_tools = metadata.setdefault("tools_completed", [])
    if tool_name not in completed_tools:
        completed_tools.append(tool_name)


def _mark_tool_skipped(metadata: dict, tool_name: str, reason: str) -> None:
    skipped_tools = metadata.setdefault("tools_skipped", [])
    skipped_tools.append({"tool": tool_name, "reason": reason})


def _mark_tool_failed(metadata: dict, tool_name: str, reason: str) -> None:
    failed_tools = metadata.setdefault("tools_failed", [])
    failed_tools.append({"tool": tool_name, "reason": reason})


def _mark_tool_parse_warning(metadata: dict, tool_name: str, message: str) -> None:
    parse_warnings = metadata.setdefault("tools_parse_warnings", [])
    warning = {"tool": tool_name, "message": message}
    if warning not in parse_warnings:
        parse_warnings.append(warning)


def _record_tool_decision(metadata: dict, decision: WorkflowDecision) -> None:
    decisions = metadata.setdefault("tool_decisions", {})
    decisions[decision.tool_name] = {
        "should_run": decision.should_run,
        "reason": decision.reason,
        "input_description": decision.input_description,
        "output_description": decision.output_description,
        "skip_reason": decision.skip_reason,
    }


def _record_tool_run(metadata: dict, result) -> None:
    tool_runs = metadata.setdefault("tool_runs", [])
    command = result.command if isinstance(result.command, list) else [str(result.command)]
    tool_runs.append(
        {
            "tool": result.tool_name,
            "command": shlex.join(command),
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "duration_seconds": result.duration_seconds,
            "stdout_path": result.stdout_path,
            "stderr_path": result.stderr_path,
        }
    )


def _normalize_result_view(view: str) -> str:
    normalized_view = view.lower()
    if normalized_view not in VALID_RESULT_VIEWS:
        valid_views = ", ".join(VALID_RESULT_VIEWS)
        raise ValueError(f"Invalid view '{view}'. Valid: {valid_views}.")
    return normalized_view


def _parse_with_warnings(
    tool_name: str,
    parser,
    metadata: dict,
    scan_folder: Path,
    *args,
    verbose: bool = False,
):
    parse_warnings: list[str] = []
    try:
        parsed_items = parser(*args, parse_warnings=parse_warnings)
    except TypeError:
        try:
            parsed_items = parser(*args)
        except Exception as exc:  # pragma: no cover - exercised through CLI tests
            return _handle_parser_exception(tool_name, exc, metadata, scan_folder, verbose)
    except Exception as exc:
        return _handle_parser_exception(tool_name, exc, metadata, scan_folder, verbose)

    for warning in parse_warnings:
        _mark_tool_parse_warning(metadata, tool_name, warning)
        if verbose:
            _print_parse_warning(tool_name, warning)
    if parse_warnings:
        write_scan_metadata(scan_folder, metadata)
    return parsed_items


def _handle_parser_exception(
    tool_name: str,
    exc: Exception,
    metadata: dict,
    scan_folder: Path,
    verbose: bool = False,
) -> list:
    message = f"Parser failed safely: {exc.__class__.__name__}"
    _mark_tool_parse_warning(metadata, tool_name, message)
    write_scan_metadata(scan_folder, metadata)
    if verbose:
        _print_parse_warning(tool_name, message)
    return []


def _persist_tool_streams(scan_folder: Path, result) -> None:
    raw_dir = scan_folder / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    if result.stderr and not result.stderr_path:
        stderr_path = raw_dir / f"{result.tool_name}.stderr.txt"
        stderr_path.write_text(result.stderr, encoding="utf-8")
        result.stderr_path = str(stderr_path)
    if result.stdout and not result.stdout_path:
        stdout_path = raw_dir / f"{result.tool_name}.stdout.txt"
        stdout_path.write_text(result.stdout, encoding="utf-8")
        result.stdout_path = str(stdout_path)


def _error_summary(text: str) -> str:
    if not text:
        return "-"
    lines = text.strip().splitlines()
    summary = "\n".join(lines[:ERROR_SUMMARY_MAX_LINES]).strip()
    if len(summary) > ERROR_SUMMARY_MAX_CHARS:
        summary = summary[:ERROR_SUMMARY_MAX_CHARS].rstrip()
    if len(lines) > ERROR_SUMMARY_MAX_LINES or len(text.strip()) > len(summary):
        summary = f"{summary}\n..."
    return summary


def _top_technologies_by_host(technologies: list) -> str:
    host_technologies: dict[str, list[str]] = {}
    for technology in technologies:
        names = host_technologies.setdefault(technology.host, [])
        if technology.name not in names:
            names.append(technology.name)

    if not host_technologies:
        return "-"

    return "; ".join(
        f"{host}: {', '.join(names[:3])}"
        for host, names in sorted(host_technologies.items())
    )


def _severity_counts(vulnerabilities: list) -> dict[str, int]:
    counts = {
        "informational": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    for vulnerability in vulnerabilities:
        severity = vulnerability.severity.lower()
        if severity == "info":
            severity = "informational"
        if severity in counts:
            counts[severity] += 1

    return counts


def _print_workflow_decision(decision: WorkflowDecision) -> None:
    console.print(f"[bold]Workflow Decision:[/bold] {decision.tool_name}")
    console.print(f"Why: {decision.reason}")
    console.print(f"Input: {decision.input_description}")
    console.print(f"Output: {decision.output_description}")
    if not decision.should_run:
        console.print(f"Skipped: {decision.skip_reason}")


def _print_skipped_step(decision: WorkflowDecision) -> None:
    console.print(
        f"[yellow]Skipped {decision.tool_name}:[/yellow] {decision.skip_reason}"
    )


def _print_error_panel(title: str, message: str) -> None:
    console.print(Panel.fit(message, title=title, style="bold red"))


def _print_target_summary(scan_target: Target, selected_mode: str, output_dir: Path) -> None:
    table = Table(title="Target Summary")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Target", scan_target.value)
    table.add_row("Target Type", scan_target.kind)
    table.add_row("Scan Mode", selected_mode)
    table.add_row("Authorization", "Confirmed")
    table.add_row("Output Directory", str(output_dir))
    console.print(table)


def _print_workflow_summary(workflow_steps: list) -> None:
    workflow_table = Table(title="Workflow Summary")
    workflow_table.add_column("Step", justify="right")
    workflow_table.add_column("Tool", style="bold")
    workflow_table.add_column("Purpose")
    for index, step in enumerate(workflow_steps, start=1):
        workflow_table.add_row(str(index), step.name, step.description)
    console.print(workflow_table)


def _print_step_progress(tool_name: str, status: str, detail: str = "") -> None:
    message = f"[bold]{tool_name}[/bold]: {status}"
    if detail:
        message = f"{message}\n{detail}"
    console.print(Panel.fit(message, title="Step Progress"))


def _print_minimal_progress(index: int, total: int, tool_name: str, status: str) -> None:
    console.print(f"[{index}/{total}] {tool_name} {status}", markup=False)


def _result_status(result) -> str:
    if result.timed_out:
        return "timed out"
    if result.exit_code == 127:
        return "missing"
    if result.exit_code != 0:
        return "failed"
    return "completed"


def _finalize_completed_tool(
    metadata: dict,
    scan_folder: Path,
    tool_name: str,
    step_index: int,
    total_steps: int,
    verbose: bool,
    dry_run: bool = False,
) -> None:
    _mark_tool_completed(metadata, tool_name)
    write_scan_metadata(scan_folder, metadata)
    if dry_run:
        return
    if verbose:
        _print_step_progress(tool_name, "Completed")
    else:
        _print_minimal_progress(step_index, total_steps, tool_name, "completed")


def _finalize_skipped_tool(
    metadata: dict,
    scan_folder: Path,
    decision: WorkflowDecision,
    step_index: int,
    total_steps: int,
    verbose: bool,
    dry_run: bool,
    explain: bool,
) -> None:
    _mark_tool_skipped(metadata, decision.tool_name, decision.skip_reason)
    write_scan_metadata(scan_folder, metadata)
    if verbose or dry_run or explain:
        _print_skipped_step(decision)
    if not dry_run and not verbose and not explain:
        _print_minimal_progress(step_index, total_steps, decision.tool_name, "skipped")


def _print_result_progress(
    result,
    step_index: int,
    total_steps: int,
    verbose: bool,
    dry_run: bool,
) -> None:
    if not dry_run and not verbose:
        _print_minimal_progress(
            step_index,
            total_steps,
            result.tool_name,
            _result_status(result),
        )


def _print_missing_tool(tool_check, decision: WorkflowDecision, result=None) -> None:
    table = Table(title="Missing External Tool")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Tool", tool_check.tool.name)
    table.add_row("Why Needed", decision.reason)
    if result is not None:
        table.add_row("Exit Code", str(result.exit_code))
        table.add_row("Timed Out", str(result.timed_out))
        if result.stderr:
            table.add_row("Error Summary", _error_summary(result.stderr))
        if result.stderr_path:
            table.add_row("Full Stderr Path", result.stderr_path)
    table.add_row("Install Note", tool_check.tool.install_note)
    table.add_row("Action", "Skipped")
    console.print(table)


def _print_tool_failure(result, decision: WorkflowDecision) -> None:
    table = Table(title="Command Execution Issue")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Tool", result.tool_name)
    table.add_row("Why Needed", decision.reason)
    table.add_row("Exit Code", str(result.exit_code))
    table.add_row("Timed Out", str(result.timed_out))
    table.add_row("Action", "Skipped downstream parsing for this tool")
    if result.stderr:
        table.add_row("Error Summary", _error_summary(result.stderr))
    if result.stderr_path:
        table.add_row("Full Stderr Path", result.stderr_path)
    if result.stdout_path:
        table.add_row("Full Stdout Path", result.stdout_path)
    console.print(table)


def _print_parse_warning(tool_name: str, message: str) -> None:
    table = Table(title="Parse Warning")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Tool", tool_name)
    table.add_row("Warning", message)
    table.add_row("Action", "Skipped invalid parser input and continued")
    console.print(table)


def _tool_result_ok(
    result,
    decision: WorkflowDecision,
    metadata: dict,
    scan_folder: Path,
    tool_checks: dict,
    verbose: bool = False,
) -> bool:
    _persist_tool_streams(scan_folder, result)
    _record_tool_run(metadata, result)
    if result.timed_out:
        reason = "Command timed out"
        _mark_tool_failed(metadata, result.tool_name, reason)
        write_scan_metadata(scan_folder, metadata)
        if verbose:
            _print_tool_failure(result, decision)
        return False
    if result.exit_code == 127:
        reason = "Missing external tool"
        _mark_tool_skipped(metadata, result.tool_name, reason)
        write_scan_metadata(scan_folder, metadata)
        tool_check = tool_checks.get(result.tool_name)
        if verbose and tool_check is not None:
            _print_missing_tool(tool_check, decision, result)
        elif verbose:
            _print_tool_failure(result, decision)
        return False
    if result.exit_code != 0:
        reason = f"Command failed with exit code {result.exit_code}"
        _mark_tool_failed(metadata, result.tool_name, reason)
        write_scan_metadata(scan_folder, metadata)
        if verbose:
            _print_tool_failure(result, decision)
        return False
    return True


def _print_findings_summary(findings: list) -> None:
    findings_table = Table(title="Correlated Findings")
    findings_table.add_column("Severity", style="bold")
    findings_table.add_column("Finding title")
    findings_table.add_column("Host/URL")
    findings_table.add_column("Risk score", justify="right")

    for finding in findings:
        findings_table.add_row(
            finding.severity,
            finding.title,
            finding.affected_url or finding.affected_host,
            str(finding.risk_score),
        )

    console.print(findings_table)


def _print_report_paths(generated_reports: dict) -> None:
    if not generated_reports:
        return
    report_table = Table(title="Report Paths")
    report_table.add_column("Format", style="bold")
    report_table.add_column("Path")
    for report_format, path in generated_reports.items():
        report_table.add_row(report_format, str(path))
    console.print(report_table)


def _print_comparison_tables(comparison: dict) -> None:
    summary_table = Table(title="ReconFlow Scan Comparison")
    summary_table.add_column("Change Type", style="bold")
    summary_table.add_column("Count", justify="right")

    details_table = Table(title="Comparison Details")
    details_table.add_column("Change Type", style="bold")
    details_table.add_column("Value")

    for field_name in COMPARISON_FIELDS:
        values = comparison.get(field_name, [])
        label = field_name.replace("_", " ").title()
        summary_table.add_row(label, str(len(values)))
        if values:
            for value in values:
                details_table.add_row(label, value)
        else:
            details_table.add_row(label, "-")

    console.print(summary_table)
    console.print(details_table)


def render_raw_cli_results(context: dict) -> None:
    """Render detailed tool-by-tool scan results."""
    console.print("[bold cyan]Raw Scan Results[/bold cyan]")
    overview = context["scan_overview"]
    overview_table = Table(title="Scan Metadata")
    overview_table.add_column("Field", style="bold")
    overview_table.add_column("Value")
    overview_table.add_row("Target", overview["target"])
    overview_table.add_row("Target Type", overview["target_type"])
    overview_table.add_row("Scan Mode", overview["scan_mode"])
    overview_table.add_row("Scan Status", overview["scan_status"])
    overview_table.add_row("Confidence", overview["confidence"])
    overview_table.add_row("Overall Risk Score", str(overview["overall_risk_score"]))
    overview_table.add_row("Risk Level", overview["risk_level"])
    console.print(overview_table)

    console.print("\n[bold]Tool-by-Tool Results[/bold]")
    for tool in context["tool_results"]:
        console.print(f"\n[bold]Tool {tool['index']}: {tool['tool']}[/bold]")
        console.print(f"Tool: {tool['tool']}")
        console.print(f"Status: {tool['status']}")
        console.print(f"Reason: {tool['why']}")
        if tool["parse_warnings"]:
            console.print(f"Parse Warning: {'; '.join(tool['parse_warnings'])}")
        if tool["command_summary"] != "-":
            console.print(f"Command: {tool['command_summary']}")
        console.print("Results:")
        _render_raw_tool_data(tool)
        console.print("Artifacts:")
        console.print(f"- Raw: {tool['raw_output_path']}")
        console.print(f"- Parsed: {tool['parsed_output_path']}")

    _render_correlated_findings(context["correlated_findings"])
    console.print(
        f"\n[bold]Overall Risk Score:[/bold] "
        f"{context['overall_risk_score']}/100 ({context['risk_level']})"
    )
    _render_report_paths(context["report_paths"])


def render_summary_cli_results(context: dict) -> None:
    """Render a concise executive-style scan summary."""
    console.print("[bold cyan]Summary Scan Results[/bold cyan]")
    overview = context["scan_overview"]
    overview_table = Table(title="Scan Result")
    overview_table.add_column("Field", style="bold")
    overview_table.add_column("Value")
    overview_table.add_row("Target", overview["target"])
    overview_table.add_row("Mode", overview["scan_mode"])
    overview_table.add_row("Scan Status", overview["scan_status"])
    overview_table.add_row("Confidence", overview["confidence"])
    overview_table.add_row("Risk", overview["risk_level"])
    overview_table.add_row("Reports generated", "Summary and raw reports")
    console.print(overview_table)

    if context["what_was_found"]["items"]:
        found_table = Table(title="What Was Found")
        found_table.add_column("Finding", style="bold")
        found_table.add_column("Count", justify="right")
        for item in context["what_was_found"]["items"]:
            found_table.add_row(item["label"], str(item["count"]))
        console.print(found_table)

    if context["important_observations"]:
        observations_table = Table(title="Important Observations")
        observations_table.add_column("Observation")
        for observation in context["important_observations"]:
            observations_table.add_row(
                f"{observation['title']} - {observation['detail']}"
            )
        console.print(observations_table)

    if context["vulnerability_summary"]:
        vulnerability_table = Table(title="Vulnerability Summary")
        vulnerability_table.add_column("Severity", style="bold")
        vulnerability_table.add_column("Finding")
        vulnerability_table.add_column("Affected")
        for severity, vulnerabilities in context["vulnerability_summary"].items():
            for vulnerability in vulnerabilities:
                vulnerability_table.add_row(
                    severity,
                    vulnerability["name"],
                    vulnerability["affected"],
                )
        console.print(vulnerability_table)

    if context["correlated_findings"]:
        correlated_table = Table(title="Correlated Findings")
        correlated_table.add_column("Severity", style="bold")
        correlated_table.add_column("Finding")
        correlated_table.add_column("Affected")
        correlated_table.add_column("Risk", justify="right")
        for finding in context["correlated_findings"]:
            correlated_table.add_row(
                finding["severity"],
                finding["title"],
                finding["affected"],
                str(finding["risk_score"]),
            )
        console.print(correlated_table)

    if context["issues_during_scan"]["has_issues"]:
        _render_summary_issues(context["issues_during_scan"])

    actions_table = Table(title="Recommended Next Actions")
    actions_table.add_column("Action")
    for action in context["recommended_actions"]:
        actions_table.add_row(action)
    console.print(actions_table)

    execution_table = Table(title="Tool Execution Summary")
    execution_table.add_column("Status", style="bold")
    execution_table.add_column("Tools")
    tool_summary = context["tool_execution_summary"]
    execution_table.add_row("Completion", tool_summary["completion_status"])
    execution_table.add_row(
        "Completed",
        ", ".join(tool_summary["completed_tools"]) or "-",
    )
    execution_table.add_row("Skipped", ", ".join(tool_summary["skipped_tools"]) or "-")
    execution_table.add_row("Missing", ", ".join(tool_summary["missing_tools"]) or "-")
    execution_table.add_row("Failed", ", ".join(tool_summary["failed_tools"]) or "-")
    execution_table.add_row(
        "Timed out",
        ", ".join(tool_summary["timed_out_tools"]) or "-",
    )
    execution_table.add_row(
        "Parse warnings",
        "; ".join(tool_summary["parse_warnings"]) or "-",
    )
    console.print(execution_table)
    _render_report_paths(context["report_paths"])


def _render_raw_tool_data(tool: dict) -> None:
    if tool["result_count"] == 0:
        console.print("- No results found")
        return

    result_type = tool["result_type"]
    if result_type == "subdomains":
        lines = [str(subdomain) for subdomain in tool["results"]]
    elif result_type == "assets":
        lines = [
            (
                f"{asset.get('hostname', '-')} -> "
                f"{asset.get('ip') or '-'} ({asset.get('record_type') or '-'})"
            )
            for asset in tool["results"]
        ]
    elif result_type == "services":
        lines = [
            (
                f"{service.get('host', '-')} "
                f"{service.get('protocol', 'tcp')}/{service.get('port', '-')} "
                f"{service.get('service_name') or '-'} "
                f"{service.get('product') or ''}"
            ).strip()
            for service in tool["results"]
        ]
    elif result_type == "live_hosts":
        lines = [
            (
                f"{host.get('url', '-')} [{host.get('status_code') or '-'}] "
                f"{host.get('title') or ''} "
                f"{', '.join(host.get('technologies') or [])}"
            ).strip()
            for host in tool["results"]
        ]
    elif result_type == "technologies":
        lines = [
            (
                f"{technology.get('host', '-')}: {technology.get('name', '-')}"
                f"{_value_suffix(technology.get('version'))}"
                f"{_category_suffix(technology.get('category'))}"
            )
            for technology in tool["results"]
        ]
    elif result_type == "endpoints":
        lines = [
            (
                f"{endpoint.get('url', '-')} [{endpoint.get('status_code') or '-'}]"
                f"{' [interesting]' if endpoint.get('interesting') else ''}"
            )
            for endpoint in tool["results"]
        ]
    elif result_type == "crawled_urls":
        _render_grouped_crawled_urls(tool)
        return
    elif result_type == "vulnerabilities":
        lines = []
        for severity, vulnerabilities in tool["vulnerabilities_by_severity"].items():
            for vulnerability in vulnerabilities:
                lines.append(
                    (
                        f"{severity}: {vulnerability.get('name', '-')} on "
                        f"{vulnerability.get('matched_url') or vulnerability.get('host', '-')}"
                    )
                )
    elif result_type == "screenshots":
        lines = [
            (
                f"{screenshot.get('url', '-')} -> "
                f"{screenshot.get('screenshot_path') or 'missing'} "
                f"({screenshot.get('status') or '-'})"
            )
            for screenshot in tool["results"]
        ]
    else:
        console.print("- No results found")
        return

    _render_limited_lines(
        lines,
        RAW_RESULT_LIMITS.get(result_type, 20),
        tool["result_count"],
        tool["parsed_output_path"],
    )


def _render_limited_lines(
    lines: list[str],
    limit: int,
    total: int,
    full_results_path: str,
) -> None:
    for line in lines[:limit]:
        console.print(f"- {line}")
    if total > limit:
        console.print(
            f"Showing {limit} of {total} results. "
            f"Full results saved to {full_results_path}"
        )


def _render_grouped_crawled_urls(tool: dict) -> None:
    groups = tool.get("url_groups") or {}
    rendered = 0
    limit = RAW_RESULT_LIMITS["crawled_urls"]
    labels = [
        ("Pages", groups.get("pages", [])),
        ("API-like endpoints", groups.get("api_like", [])),
        ("Static assets", groups.get("static_assets", [])),
    ]
    for label, items in labels:
        if not items or rendered >= limit:
            continue
        console.print(f"{label}:")
        remaining = limit - rendered
        for item in items[:remaining]:
            console.print(f"- {item.get('url', '-')}")
        rendered += min(len(items), remaining)
    if tool["result_count"] > limit:
        console.print(
            f"Showing {limit} of {tool['result_count']} results. "
            f"Full results saved to {tool['parsed_output_path']}"
        )


def _value_suffix(value) -> str:
    if value is None or value == "":
        return ""
    return f" {value}"


def _category_suffix(value) -> str:
    if value is None or value == "":
        return ""
    return f" ({value})"


def _render_summary_issues(issues: dict) -> None:
    table = Table(title="Issues During Scan")
    table.add_column("Group", style="bold")
    table.add_column("Details")
    for label, key in (
        ("Timed out", "timed_out"),
        ("Missing", "missing"),
        ("Failed", "failed"),
    ):
        entries = issues.get(key, [])
        if not entries:
            continue
        details = []
        for item in entries:
            stderr_path = item.get("stderr_path")
            suffix = f" Full error saved to {stderr_path}" if stderr_path else ""
            details.append(f"{item.get('tool', '-')}: {item.get('reason', '-')}.{suffix}")
        table.add_row(label, "\n".join(details))
    parse_warnings = issues.get("parse_warnings", [])
    if parse_warnings:
        table.add_row(
            "Parse warnings",
            "\n".join(
                f"{item.get('tool', '-')}: {item.get('message', '-')}"
                for item in parse_warnings
            ),
        )
    console.print(table)


def _render_correlated_findings(findings: list) -> None:
    table = Table(title="Correlated Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Finding")
    table.add_column("Host/URL")
    table.add_column("Risk", justify="right")
    if not findings:
        table.add_row("-", "No correlated findings were generated.", "-", "0")
    else:
        for finding in findings:
            table.add_row(
                str(finding.get("severity", "-")),
                str(finding.get("title", "-")),
                str(finding.get("affected_url") or finding.get("affected_host", "-")),
                str(finding.get("risk_score", 0)),
            )
    console.print(table)


def _render_report_paths(report_paths: dict) -> None:
    console.print("\n[bold]Reports saved:[/bold]")
    console.print(
        f"- Summary: {report_paths.get('summary_html_report', 'reports/report_summary.html')}"
    )
    console.print(f"- Raw: {report_paths.get('raw_html_report', 'reports/report_raw.html')}")


@app.callback()
def callback() -> None:
    """ReconFlow command group callback."""


@app.command("scan")
def scan(
    target: str,
    i_authorize: bool = typer.Option(
        False,
        "--i-authorize",
        help="Confirm you own or have explicit permission to test the target.",
    ),
    mode: str | None = typer.Option(None, "--mode", help="Selected scan mode."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show commands that would run without executing external tools.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Explain why each workflow step runs or is skipped.",
    ),
    wordlist: str | None = typer.Option(
        None,
        "--wordlist",
        help="Wordlist for Feroxbuster content discovery.",
    ),
    view: str = typer.Option(
        "summary",
        "--view",
        help="Result view for terminal output: raw or summary.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Show detailed execution progress, decisions, and command issues.",
    ),
) -> None:
    """Validate and prepare a placeholder recon scan workflow for a target."""
    config = load_config()
    selected_mode = (mode or config.default_mode).lower()

    if not i_authorize:
        _print_error_panel(
            "Missing Authorization",
            (
                f"{AUTHORIZATION_WARNING}\n"
                "ReconFlow is only for systems you own or have explicit permission to test."
            ),
        )
        raise typer.Exit(code=1)

    scan_target = Target.from_value(target)
    if scan_target.kind == "invalid":
        _print_error_panel(
            "Invalid Target",
            f"Could not parse target: {target}\nUse a domain, IP address, or URL.",
        )
        raise typer.Exit(code=1)

    try:
        selected_view = _normalize_result_view(view)
    except ValueError as exc:
        _print_error_panel("Invalid View", str(exc))
        raise typer.Exit(code=1) from exc

    try:
        workflow_steps = get_workflow_steps(selected_mode, config.enabled_tools)
    except ValueError as exc:
        _print_error_panel("Invalid Scan Mode", str(exc))
        raise typer.Exit(code=1) from exc

    metadata = create_scan_folder(
        target=scan_target.value,
        target_type=scan_target.kind,
        mode=selected_mode,
        base_dir=config.output_directory,
        tools_planned=[step.name for step in workflow_steps],
    )
    orchestrator = Orchestrator()
    workflow_state = WorkflowState(
        target=scan_target.value,
        target_type=scan_target.kind,
        mode=selected_mode,
        planned_tools=metadata["tools_planned"],
    )
    scan_folder = Path(metadata["output_dir"])
    tool_checks = {result.tool.name: result for result in check_required_tools()}
    if dry_run or explain or verbose:
        _print_target_summary(scan_target, selected_mode, scan_folder)
        _print_workflow_summary(workflow_steps)
    selected_wordlist_path = wordlist or config.wordlist_path
    raw_subfinder_path = scan_folder / "raw" / "subfinder.txt"
    parsed_subdomains_path = scan_folder / "parsed" / "subdomains.json"
    subfinder_target = select_subfinder_domain(scan_target.value)
    subfinder_command = build_subfinder_command(subfinder_target, raw_subfinder_path)
    subdomains: list[str] = []
    subfinder_result = None
    raw_dnsx_path = scan_folder / "raw" / "dnsx.jsonl"
    dnsx_input_path = scan_folder / "raw" / "dnsx_input.txt"
    parsed_assets_path = scan_folder / "parsed" / "assets.json"
    dnsx_command = build_dnsx_command(dnsx_input_path, raw_dnsx_path)
    assets = []
    dnsx_result = None
    raw_nmap_path = scan_folder / "raw" / "nmap.xml"
    parsed_services_path = scan_folder / "parsed" / "services.json"
    services = []
    nmap_result = None
    raw_httpx_path = scan_folder / "raw" / "httpx.jsonl"
    parsed_live_hosts_path = scan_folder / "parsed" / "live_hosts.json"
    live_hosts = []
    httpx_result = None
    raw_whatweb_path = scan_folder / "raw" / "whatweb.json"
    parsed_technologies_path = scan_folder / "parsed" / "technologies.json"
    technologies = []
    whatweb_result = None
    raw_feroxbuster_path = scan_folder / "raw" / "feroxbuster.json"
    parsed_endpoints_path = scan_folder / "parsed" / "endpoints.json"
    feroxbuster_result = None
    endpoints = []
    raw_katana_path = scan_folder / "raw" / "katana.jsonl"
    parsed_crawled_urls_path = scan_folder / "parsed" / "crawled_urls.json"
    katana_result = None
    crawled_urls = []
    raw_nuclei_path = scan_folder / "raw" / "nuclei.jsonl"
    parsed_vulnerabilities_path = scan_folder / "parsed" / "vulnerabilities.json"
    nuclei_result = None
    vulnerabilities = []
    screenshots_dir = scan_folder / "screenshots"
    raw_gowitness_jsonl_path = scan_folder / "raw" / "gowitness.jsonl"
    parsed_screenshots_path = scan_folder / "parsed" / "screenshots.json"
    gowitness_result = None
    screenshots = []

    total_steps = len(workflow_steps)
    for step_index, workflow_step in enumerate(workflow_steps, start=1):
        tool_name = workflow_step.name
        decision = orchestrator.decide(tool_name, workflow_state)
        _record_tool_decision(metadata, decision)
        if explain:
            _print_workflow_decision(decision)
        if not decision.should_run:
            _finalize_skipped_tool(
                metadata,
                scan_folder,
                decision,
                step_index,
                total_steps,
                verbose,
                dry_run,
                explain,
            )
            continue
        if verbose:
            _print_step_progress(tool_name, "Ready", decision.reason)

        if tool_name == "subfinder":
            if dry_run:
                console.print(
                    "[yellow]Dry run:[/yellow] "
                    f"would run Subfinder command: [bold]{shlex.join(subfinder_command)}[/bold]"
                )
                continue

            subfinder_result = run_subfinder(
                subfinder_target,
                scan_folder,
                timeout=config.tool_timeouts.get("subfinder"),
            )
            if not _tool_result_ok(
                subfinder_result,
                decision,
                metadata,
                scan_folder,
                tool_checks,
                verbose,
            ):
                _print_result_progress(
                    subfinder_result,
                    step_index,
                    total_steps,
                    verbose,
                    dry_run,
                )
                continue
            if subfinder_result.exit_code == 0 and raw_subfinder_path.exists():
                subdomains = parse_subfinder_output(raw_subfinder_path)
                workflow_state.subdomains = subdomains
                save_subdomains_json(subdomains, parsed_subdomains_path)
                _finalize_completed_tool(
                    metadata,
                    scan_folder,
                    "subfinder",
                    step_index,
                    total_steps,
                    verbose,
                )

        elif tool_name == "dnsx":
            if dry_run:
                console.print(
                    "[yellow]Dry run:[/yellow] "
                    "would run dnsx command after parsed subdomains are available: "
                    f"[bold]{shlex.join(dnsx_command)}[/bold]"
                )
                continue

            dnsx_result = run_dnsx(
                scan_folder,
                subdomains,
                timeout=config.tool_timeouts.get("dnsx"),
            )
            if not _tool_result_ok(
                dnsx_result,
                decision,
                metadata,
                scan_folder,
                tool_checks,
                verbose,
            ):
                _print_result_progress(dnsx_result, step_index, total_steps, verbose, dry_run)
                continue
            if dnsx_result.exit_code == 0 and raw_dnsx_path.exists():
                assets = _parse_with_warnings(
                    "dnsx",
                    parse_dnsx_jsonl,
                    metadata,
                    scan_folder,
                    raw_dnsx_path,
                    verbose=verbose,
                )
                workflow_state.resolved_hosts = [
                    asset.hostname for asset in assets if asset.is_resolved
                ]
                metadata["resolved_hostnames"] = sorted(
                    {asset.hostname for asset in assets if asset.is_resolved}
                )
                save_assets_json(assets, parsed_assets_path)
                _finalize_completed_tool(
                    metadata,
                    scan_folder,
                    "dnsx",
                    step_index,
                    total_steps,
                    verbose,
                )

        elif tool_name == "nmap":
            nmap_targets = select_nmap_targets(
                scan_target.value,
                assets if selected_mode == "deep" and workflow_state.resolved_hosts else None,
                workflow_state.resolved_hosts
                if selected_mode == "deep" and workflow_state.resolved_hosts
                else None,
            )
            metadata["nmap_target_context"] = {
                "original_target": scan_target.value,
                "scan_targets": nmap_targets,
                "resolved_hostnames": sorted(set(workflow_state.resolved_hosts)),
            }
            nmap_command = build_nmap_command(nmap_targets, raw_nmap_path)
            nmap_run_target = (
                nmap_targets[0]
                if len(nmap_targets) == 1
                else nmap_targets
            )
            if dry_run:
                console.print(
                    "[yellow]Dry run:[/yellow] "
                    f"would run Nmap command: [bold]{shlex.join(nmap_command)}[/bold]"
                )
                continue

            nmap_result = run_nmap(
                nmap_run_target,
                scan_folder,
                timeout=config.tool_timeouts.get("nmap"),
            )
            if not _tool_result_ok(
                nmap_result,
                decision,
                metadata,
                scan_folder,
                tool_checks,
                verbose,
            ):
                _print_result_progress(nmap_result, step_index, total_steps, verbose, dry_run)
                continue
            if nmap_result.exit_code == 0 and raw_nmap_path.exists():
                services = parse_nmap_xml(raw_nmap_path)
                workflow_state.nmap_web_ports = [
                    service.port
                    for service in services
                    if service.port in {80, 443, 8080, 8443, 8000, 8888}
                ]
                save_services_json(services, parsed_services_path)
                _finalize_completed_tool(
                    metadata,
                    scan_folder,
                    "nmap",
                    step_index,
                    total_steps,
                    verbose,
                )

        elif tool_name == "httpx":
            resolved_hosts = workflow_state.resolved_hosts
            httpx_inputs = select_httpx_inputs(scan_target.value, resolved_hosts)
            httpx_input_file_path = scan_folder / "raw" / "httpx_inputs.txt"
            httpx_command = build_httpx_command(
                httpx_inputs,
                raw_httpx_path,
                httpx_input_file_path if len(httpx_inputs) > 1 else None,
            )
            if dry_run:
                console.print(
                    "[yellow]Dry run:[/yellow] "
                    f"would run httpx command: [bold]{shlex.join(httpx_command)}[/bold]"
                )
                continue

            httpx_result = run_httpx(
                scan_target.value,
                scan_folder,
                resolved_hosts=resolved_hosts,
                timeout=config.tool_timeouts.get("httpx"),
            )
            if not _tool_result_ok(
                httpx_result,
                decision,
                metadata,
                scan_folder,
                tool_checks,
                verbose,
            ):
                _print_result_progress(httpx_result, step_index, total_steps, verbose, dry_run)
                continue
            if httpx_result.exit_code == 0 and raw_httpx_path.exists():
                live_hosts = _parse_with_warnings(
                    "httpx",
                    parse_httpx_jsonl,
                    metadata,
                    scan_folder,
                    raw_httpx_path,
                    verbose=verbose,
                )
                workflow_state.live_hosts = [live_host.url for live_host in live_hosts]
                save_live_hosts_json(live_hosts, parsed_live_hosts_path)
                _finalize_completed_tool(
                    metadata,
                    scan_folder,
                    "httpx",
                    step_index,
                    total_steps,
                    verbose,
                )

        elif tool_name == "whatweb":
            if dry_run:
                console.print(
                    "[yellow]Dry run:[/yellow] "
                    "would run WhatWeb after parsed live web hosts are available."
                )
                continue

            whatweb_result = run_whatweb(
                scan_folder,
                parsed_live_hosts_path,
                timeout=config.tool_timeouts.get("whatweb"),
            )
            if not _tool_result_ok(
                whatweb_result,
                decision,
                metadata,
                scan_folder,
                tool_checks,
                verbose,
            ):
                _print_result_progress(
                    whatweb_result,
                    step_index,
                    total_steps,
                    verbose,
                    dry_run,
                )
                continue
            if whatweb_result.exit_code == 0 and raw_whatweb_path.exists():
                technologies = parse_whatweb_json(raw_whatweb_path)
                save_technologies_json(technologies, parsed_technologies_path)
                _finalize_completed_tool(
                    metadata,
                    scan_folder,
                    "whatweb",
                    step_index,
                    total_steps,
                    verbose,
                )

        elif tool_name == "feroxbuster":
            if dry_run:
                console.print(
                    "[yellow]Dry run:[/yellow] "
                    "would run Feroxbuster after parsed live web hosts are available "
                    f"using wordlist [bold]{selected_wordlist_path}[/bold] "
                    f"and save raw output to [bold]{raw_feroxbuster_path}[/bold]."
                )
                continue

            feroxbuster_result = run_feroxbuster(
                scan_folder,
                parsed_live_hosts_path,
                selected_wordlist_path,
                timeout=config.tool_timeouts.get("feroxbuster"),
            )
            if not _tool_result_ok(
                feroxbuster_result,
                decision,
                metadata,
                scan_folder,
                tool_checks,
                verbose,
            ):
                _print_result_progress(
                    feroxbuster_result,
                    step_index,
                    total_steps,
                    verbose,
                    dry_run,
                )
                continue
            if feroxbuster_result.exit_code == 0 and raw_feroxbuster_path.exists():
                endpoints = _parse_with_warnings(
                    "feroxbuster",
                    parse_feroxbuster_json,
                    metadata,
                    scan_folder,
                    raw_feroxbuster_path,
                    verbose=verbose,
                )
                save_endpoints_json(endpoints, parsed_endpoints_path)
                _finalize_completed_tool(
                    metadata,
                    scan_folder,
                    "feroxbuster",
                    step_index,
                    total_steps,
                    verbose,
                )

        elif tool_name == "katana":
            if dry_run:
                console.print(
                    "[yellow]Dry run:[/yellow] "
                    "would run Katana after parsed live web hosts are available "
                    f"and save raw output to [bold]{raw_katana_path}[/bold]."
                )
                continue

            katana_result = run_katana(
                scan_folder,
                parsed_live_hosts_path,
                timeout=config.tool_timeouts.get("katana"),
            )
            if not _tool_result_ok(
                katana_result,
                decision,
                metadata,
                scan_folder,
                tool_checks,
                verbose,
            ):
                _print_result_progress(katana_result, step_index, total_steps, verbose, dry_run)
                continue
            if katana_result.exit_code == 0 and raw_katana_path.exists():
                crawled_urls = _parse_with_warnings(
                    "katana",
                    parse_katana_jsonl,
                    metadata,
                    scan_folder,
                    raw_katana_path,
                    verbose=verbose,
                )
                save_crawled_urls_json(crawled_urls, parsed_crawled_urls_path)
                endpoints = merge_interesting_crawled_urls_into_endpoints(
                    crawled_urls,
                    parsed_endpoints_path,
                )
                _finalize_completed_tool(
                    metadata,
                    scan_folder,
                    "katana",
                    step_index,
                    total_steps,
                    verbose,
                )

        elif tool_name == "nuclei":
            if dry_run:
                console.print(
                    "[yellow]Dry run:[/yellow] "
                    "would run Nuclei after parsed live web hosts are available "
                    f"and save raw output to [bold]{raw_nuclei_path}[/bold]."
                )
                continue

            nuclei_result = run_nuclei(
                scan_folder,
                parsed_live_hosts_path,
                timeout=config.tool_timeouts.get("nuclei"),
            )
            if not _tool_result_ok(
                nuclei_result,
                decision,
                metadata,
                scan_folder,
                tool_checks,
                verbose,
            ):
                _print_result_progress(nuclei_result, step_index, total_steps, verbose, dry_run)
                continue
            if nuclei_result.exit_code == 0 and raw_nuclei_path.exists():
                vulnerabilities = _parse_with_warnings(
                    "nuclei",
                    parse_nuclei_jsonl,
                    metadata,
                    scan_folder,
                    raw_nuclei_path,
                    verbose=verbose,
                )
                save_vulnerabilities_json(
                    vulnerabilities,
                    parsed_vulnerabilities_path,
                )
                _finalize_completed_tool(
                    metadata,
                    scan_folder,
                    "nuclei",
                    step_index,
                    total_steps,
                    verbose,
                )

        elif tool_name == "gowitness":
            if dry_run:
                console.print(
                    "[yellow]Dry run:[/yellow] "
                    "would run Gowitness after parsed live web hosts are available "
                    f"and save screenshots under [bold]{screenshots_dir}[/bold]."
                )
                continue

            gowitness_result = run_gowitness(
                scan_folder,
                parsed_live_hosts_path,
                timeout=config.tool_timeouts.get("gowitness"),
            )
            if not _tool_result_ok(
                gowitness_result,
                decision,
                metadata,
                scan_folder,
                tool_checks,
                verbose,
            ):
                _print_result_progress(
                    gowitness_result,
                    step_index,
                    total_steps,
                    verbose,
                    dry_run,
                )
                continue
            if gowitness_result.exit_code == 0:
                gowitness_targets = load_gowitness_targets(parsed_live_hosts_path)
                if raw_gowitness_jsonl_path.exists():
                    screenshots = _parse_with_warnings(
                        "gowitness",
                        parse_gowitness_jsonl,
                        metadata,
                        scan_folder,
                        raw_gowitness_jsonl_path,
                        verbose=verbose,
                    )
                if not screenshots:
                    screenshots = collect_screenshot_metadata(
                        gowitness_targets,
                        screenshots_dir,
                    )
                save_screenshots_json(screenshots, parsed_screenshots_path)
                _finalize_completed_tool(
                    metadata,
                    scan_folder,
                    "gowitness",
                    step_index,
                    total_steps,
                    verbose,
                )

    correlation_result = correlate_scan(scan_folder)
    findings = correlation_result.findings
    overall_risk_score = correlation_result.overall_risk_score
    parsed_findings_path = correlation_result.output_path
    metadata["overall_risk_score"] = overall_risk_score
    metadata["findings_count"] = len(findings)
    write_scan_metadata(scan_folder, metadata)
    if has_parsed_data(scan_folder):
        generate_all_report_views(scan_folder)

    if selected_view == "summary":
        render_summary_cli_results(build_summary_report_context(scan_folder))
    else:
        render_raw_cli_results(build_raw_report_context(scan_folder))

    if dry_run:
        console.print("Dry run complete. No external security tools were executed.")


@tools_app.command("check")
def tools_check() -> None:
    """Check whether supported external tools are installed."""
    table = Table(title="ReconFlow External Tool Check")
    table.add_column("Tool", style="bold")
    table.add_column("Purpose")
    table.add_column("Status")
    table.add_column("Detected Path")
    table.add_column("Install Note")

    for result in check_required_tools():
        status = "[green]Installed[/green]" if result.is_installed else "[red]Missing[/red]"
        table.add_row(
            result.tool.name,
            result.tool.purpose,
            status,
            result.detected_path or "-",
            result.tool.install_note,
        )

    console.print(table)


@app.command("history")
def history() -> None:
    """Show scan history from metadata files."""
    scans = read_scan_history()
    if not scans:
        console.print("No scans recorded yet.")
        return

    table = Table(title="ReconFlow Scan History")
    table.add_column("Scan ID", style="bold")
    table.add_column("Target")
    table.add_column("Target Type")
    table.add_column("Mode")
    table.add_column("Status")
    table.add_column("Start Time")
    table.add_column("Output Directory")

    for scan_metadata in scans:
        table.add_row(
            scan_metadata.get("scan_id", "-"),
            scan_metadata.get("target", "-"),
            scan_metadata.get("target_type", "-"),
            scan_metadata.get("mode", "-"),
            scan_metadata.get("status", "-"),
            scan_metadata.get("start_time", "-"),
            scan_metadata.get("output_dir", "-"),
        )

    console.print(table)


@app.command("report")
def report(
    scan_id: str,
    report_format: str = typer.Option(
        "all",
        "--format",
        help="Report format to generate: markdown, html, json, or all.",
    ),
    view: str = typer.Option(
        "summary",
        "--view",
        help="Report view to generate: raw or summary.",
    ),
) -> None:
    """Generate reports for an existing scan."""
    config = load_config()
    scan_folder = find_scan_folder(scan_id, config.output_directory)
    if scan_folder is None:
        _print_error_panel(
            "Missing Scan ID",
            f"Scan ID was not found: {scan_id}",
        )
        raise typer.Exit(code=1)
    if not has_parsed_data(scan_folder):
        _print_error_panel(
            "Missing Parsed Data",
            f"No parsed JSON artifacts were found for scan: {scan_id}",
        )
        raise typer.Exit(code=1)

    try:
        selected_view = _normalize_result_view(view)
        generated_reports = generate_reports(scan_folder, report_format, selected_view)
    except ValueError as exc:
        _print_error_panel("Invalid Report Request", str(exc))
        raise typer.Exit(code=1) from exc

    for generated_format, path in generated_reports.items():
        console.print(
            f"Generated {generated_format} report ({selected_view} view) "
            f"for [bold]{scan_id}[/bold]: {path}"
        )


@app.command("compare")
def compare(scan_id_1: str, scan_id_2: str) -> None:
    """Compare parsed JSON artifacts from two scans."""
    config = load_config()
    scan_1_folder = find_scan_folder(scan_id_1, config.output_directory)
    scan_2_folder = find_scan_folder(scan_id_2, config.output_directory)
    if scan_1_folder is None:
        _print_error_panel("Missing Scan ID", f"Scan ID was not found: {scan_id_1}")
        raise typer.Exit(code=1)
    if scan_2_folder is None:
        _print_error_panel("Missing Scan ID", f"Scan ID was not found: {scan_id_2}")
        raise typer.Exit(code=1)

    comparison = compare_scans(
        scan_1_folder,
        scan_2_folder,
        scan_id_1,
        scan_id_2,
        output_base_dir=config.output_directory,
    )
    _print_comparison_tables(comparison)
    console.print(f"Comparison saved to: {comparison['output_path']}")


@app.command("version")
def version() -> None:
    """Show application version."""
    console.print(f"{APP_NAME} v{APP_VERSION}")


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()
