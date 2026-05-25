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
        }
    )


def _normalize_result_view(view: str) -> str:
    normalized_view = view.lower()
    if normalized_view not in VALID_RESULT_VIEWS:
        valid_views = ", ".join(VALID_RESULT_VIEWS)
        raise ValueError(f"Invalid view '{view}'. Valid: {valid_views}.")
    return normalized_view


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


def _print_missing_tool(tool_check, decision: WorkflowDecision) -> None:
    table = Table(title="Missing External Tool")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Tool", tool_check.tool.name)
    table.add_row("Why Needed", decision.reason)
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
        table.add_row("Error", result.stderr.strip())
    console.print(table)


def _tool_result_ok(
    result,
    decision: WorkflowDecision,
    metadata: dict,
    scan_folder: Path,
    tool_checks: dict,
) -> bool:
    _record_tool_run(metadata, result)
    if result.timed_out:
        reason = "Command timed out"
        _mark_tool_failed(metadata, result.tool_name, reason)
        write_scan_metadata(scan_folder, metadata)
        _print_tool_failure(result, decision)
        return False
    if result.exit_code == 127:
        reason = "Missing external tool"
        _mark_tool_skipped(metadata, result.tool_name, reason)
        write_scan_metadata(scan_folder, metadata)
        tool_check = tool_checks.get(result.tool_name)
        if tool_check is not None:
            _print_missing_tool(tool_check, decision)
        else:
            _print_tool_failure(result, decision)
        return False
    if result.exit_code != 0:
        reason = f"Command failed with exit code {result.exit_code}"
        _mark_tool_failed(metadata, result.tool_name, reason)
        write_scan_metadata(scan_folder, metadata)
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
    console.print(Panel.fit("Raw Scan Results", style="bold cyan"))
    overview = context["scan_overview"]
    overview_table = Table(title="Scan Overview")
    overview_table.add_column("Field", style="bold")
    overview_table.add_column("Value")
    overview_table.add_row("Target", overview["target"])
    overview_table.add_row("Target Type", overview["target_type"])
    overview_table.add_row("Scan Mode", overview["scan_mode"])
    overview_table.add_row("Overall Risk Score", str(overview["overall_risk_score"]))
    overview_table.add_row("Risk Level", overview["risk_level"])
    console.print(overview_table)

    console.print(Panel.fit("Tool Results", style="bold"))
    for tool in context["tool_results"]:
        details = Table.grid(padding=(0, 1))
        details.add_column(style="bold")
        details.add_column()
        details.add_row("Status", tool["status"])
        details.add_row("Why", tool["why"])
        details.add_row("Command", tool["command_summary"])
        details.add_row("Raw Output", tool["raw_output_path"])
        details.add_row("Parsed Output", tool["parsed_output_path"])
        console.print(Panel(details, title=f"Tool {tool['index']}: {tool['tool']}"))
        _render_raw_tool_data(tool)

    _render_correlated_findings(context["correlated_findings"])
    risk_table = Table(title="Overall Risk Score")
    risk_table.add_column("Score", justify="right")
    risk_table.add_column("Level")
    risk_table.add_row(
        str(context["overall_risk_score"]),
        context["risk_level"],
    )
    console.print(risk_table)
    _render_report_paths(context["report_paths"])


def render_summary_cli_results(context: dict) -> None:
    """Render a concise executive-style scan summary."""
    console.print(Panel.fit("Summary Scan Results", style="bold cyan"))
    overview = context["scan_overview"]
    overview_table = Table(title="Scan Overview")
    overview_table.add_column("Field", style="bold")
    overview_table.add_column("Value")
    overview_table.add_row("Target", overview["target"])
    overview_table.add_row("Target Type", overview["target_type"])
    overview_table.add_row("Scan Mode", overview["scan_mode"])
    overview_table.add_row("Scan Time", overview["scan_time"])
    overview_table.add_row("Overall Risk Score", str(overview["overall_risk_score"]))
    overview_table.add_row("Risk Level", overview["risk_level"])
    console.print(overview_table)

    if context["key_findings"]["items"]:
        key_table = Table(title="Key Findings")
        key_table.add_column("Finding")
        for item in context["key_findings"]["items"]:
            key_table.add_row(item)
        console.print(key_table)

    if context["security_observations"]:
        observations_table = Table(title="Security-Relevant Observations")
        observations_table.add_column("Type", style="bold")
        observations_table.add_column("Observation")
        for observation in context["security_observations"]:
            observations_table.add_row(
                observation["type"],
                f"{observation['title']} - {observation['detail']}",
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
        correlated_table = Table(title="Correlated Risk Findings")
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

    actions_table = Table(title="Recommended Next Actions")
    actions_table.add_column("Action")
    for action in context["recommended_actions"]:
        actions_table.add_row(action)
    console.print(actions_table)

    execution_table = Table(title="Tool Execution Summary")
    execution_table.add_column("Status", style="bold")
    execution_table.add_column("Tools")
    tool_summary = context["tool_execution_summary"]
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
    console.print(execution_table)
    _render_report_paths(context["report_paths"])


def _render_raw_tool_data(tool: dict) -> None:
    if tool["result_count"] == 0:
        console.print("[dim]No results found[/dim]")
        return

    result_type = tool["result_type"]
    if result_type == "subdomains":
        table = Table(title="Discovered Subdomains")
        table.add_column("Subdomain")
        for subdomain in tool["results"]:
            table.add_row(str(subdomain))
    elif result_type == "assets":
        table = Table(title="Resolved Assets")
        table.add_column("Hostname")
        table.add_column("IP")
        table.add_column("Record Type")
        for asset in tool["results"]:
            table.add_row(
                str(asset.get("hostname", "-")),
                str(asset.get("ip") or "-"),
                str(asset.get("record_type") or "-"),
            )
    elif result_type == "services":
        table = Table(title="Open Ports and Services")
        table.add_column("Host")
        table.add_column("Port")
        table.add_column("Service")
        table.add_column("Product")
        for service in tool["results"]:
            table.add_row(
                str(service.get("host", "-")),
                f"{service.get('port', '-')}/{service.get('protocol', 'tcp')}",
                str(service.get("service_name") or "-"),
                str(service.get("product") or "-"),
            )
    elif result_type == "live_hosts":
        table = Table(title="Live Web Services")
        table.add_column("URL")
        table.add_column("Status")
        table.add_column("Title")
        table.add_column("Technologies")
        for host in tool["results"]:
            table.add_row(
                str(host.get("url", "-")),
                str(host.get("status_code") or "-"),
                str(host.get("title") or "-"),
                ", ".join(host.get("technologies") or []) or "-",
            )
    elif result_type == "technologies":
        table = Table(title="Technologies Detected")
        table.add_column("Host")
        table.add_column("Technology")
        table.add_column("Version")
        table.add_column("Category")
        for technology in tool["results"]:
            table.add_row(
                str(technology.get("host", "-")),
                str(technology.get("name", "-")),
                str(technology.get("version") or "-"),
                str(technology.get("category") or "-"),
            )
    elif result_type == "endpoints":
        table = Table(title="Endpoints Discovered")
        table.add_column("URL")
        table.add_column("Status")
        table.add_column("Interesting")
        for endpoint in tool["results"]:
            table.add_row(
                str(endpoint.get("url", "-")),
                str(endpoint.get("status_code") or "-"),
                str(endpoint.get("interesting", False)),
            )
    elif result_type == "crawled_urls":
        table = Table(title="Crawled URLs")
        table.add_column("URL")
        table.add_column("Path")
        for crawled_url in tool["results"]:
            table.add_row(
                str(crawled_url.get("url", "-")),
                str(crawled_url.get("path") or "-"),
            )
    elif result_type == "vulnerabilities":
        table = Table(title="Vulnerability Summary")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        for severity, vulnerabilities in tool["vulnerabilities_by_severity"].items():
            table.add_row(f"{severity} Findings", str(len(vulnerabilities)))
    elif result_type == "screenshots":
        table = Table(title="Screenshots Captured")
        table.add_column("URL")
        table.add_column("Screenshot Path")
        table.add_column("Status")
        for screenshot in tool["results"]:
            table.add_row(
                str(screenshot.get("url", "-")),
                str(screenshot.get("screenshot_path") or "-"),
                str(screenshot.get("status") or "-"),
            )
    else:
        console.print("[dim]No results found[/dim]")
        return

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
    report_table = Table(title="Report Paths")
    report_table.add_column("Report", style="bold")
    report_table.add_column("Path")
    report_table.add_row("Raw", report_paths["raw_report"])
    report_table.add_row("Summary", report_paths["summary_report"])
    report_table.add_row("JSON", report_paths["json_report"])
    console.print(report_table)


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
        "raw",
        "--view",
        help="Result view for terminal output: raw or summary.",
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
    parsed_screenshots_path = scan_folder / "parsed" / "screenshots.json"
    gowitness_result = None
    screenshots = []

    for workflow_step in workflow_steps:
        tool_name = workflow_step.name
        decision = orchestrator.decide(tool_name, workflow_state)
        _record_tool_decision(metadata, decision)
        if explain:
            _print_workflow_decision(decision)
        if not decision.should_run:
            _mark_tool_skipped(metadata, tool_name, decision.skip_reason)
            write_scan_metadata(scan_folder, metadata)
            _print_skipped_step(decision)
            continue
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
            ):
                continue
            if subfinder_result.exit_code == 0 and raw_subfinder_path.exists():
                subdomains = parse_subfinder_output(raw_subfinder_path)
                workflow_state.subdomains = subdomains
                save_subdomains_json(subdomains, parsed_subdomains_path)
                _mark_tool_completed(metadata, "subfinder")
                write_scan_metadata(scan_folder, metadata)

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
            if not _tool_result_ok(dnsx_result, decision, metadata, scan_folder, tool_checks):
                continue
            if dnsx_result.exit_code == 0 and raw_dnsx_path.exists():
                assets = parse_dnsx_jsonl(raw_dnsx_path)
                workflow_state.resolved_hosts = [
                    asset.hostname for asset in assets if asset.is_resolved
                ]
                save_assets_json(assets, parsed_assets_path)
                _mark_tool_completed(metadata, "dnsx")
                write_scan_metadata(scan_folder, metadata)

        elif tool_name == "nmap":
            nmap_targets = (
                workflow_state.resolved_hosts
                if selected_mode == "deep" and workflow_state.resolved_hosts
                else scan_target.value
            )
            nmap_command = build_nmap_command(nmap_targets, raw_nmap_path)
            nmap_run_target = (
                nmap_targets[0]
                if isinstance(nmap_targets, list) and len(nmap_targets) == 1
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
            if not _tool_result_ok(nmap_result, decision, metadata, scan_folder, tool_checks):
                continue
            if nmap_result.exit_code == 0 and raw_nmap_path.exists():
                services = parse_nmap_xml(raw_nmap_path)
                workflow_state.nmap_web_ports = [
                    service.port
                    for service in services
                    if service.port in {80, 443, 8080, 8443, 8000, 8888}
                ]
                save_services_json(services, parsed_services_path)
                _mark_tool_completed(metadata, "nmap")
                write_scan_metadata(scan_folder, metadata)

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
            if not _tool_result_ok(httpx_result, decision, metadata, scan_folder, tool_checks):
                continue
            if httpx_result.exit_code == 0 and raw_httpx_path.exists():
                live_hosts = parse_httpx_jsonl(raw_httpx_path)
                workflow_state.live_hosts = [live_host.url for live_host in live_hosts]
                save_live_hosts_json(live_hosts, parsed_live_hosts_path)
                _mark_tool_completed(metadata, "httpx")
                write_scan_metadata(scan_folder, metadata)

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
            ):
                continue
            if whatweb_result.exit_code == 0 and raw_whatweb_path.exists():
                technologies = parse_whatweb_json(raw_whatweb_path)
                save_technologies_json(technologies, parsed_technologies_path)
                _mark_tool_completed(metadata, "whatweb")
                write_scan_metadata(scan_folder, metadata)

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
            ):
                continue
            if feroxbuster_result.exit_code == 0 and raw_feroxbuster_path.exists():
                endpoints = parse_feroxbuster_json(raw_feroxbuster_path)
                save_endpoints_json(endpoints, parsed_endpoints_path)
                _mark_tool_completed(metadata, "feroxbuster")
                write_scan_metadata(scan_folder, metadata)

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
            if not _tool_result_ok(katana_result, decision, metadata, scan_folder, tool_checks):
                continue
            if katana_result.exit_code == 0 and raw_katana_path.exists():
                crawled_urls = parse_katana_jsonl(raw_katana_path)
                save_crawled_urls_json(crawled_urls, parsed_crawled_urls_path)
                endpoints = merge_interesting_crawled_urls_into_endpoints(
                    crawled_urls,
                    parsed_endpoints_path,
                )
                _mark_tool_completed(metadata, "katana")
                write_scan_metadata(scan_folder, metadata)

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
            if not _tool_result_ok(nuclei_result, decision, metadata, scan_folder, tool_checks):
                continue
            if nuclei_result.exit_code == 0 and raw_nuclei_path.exists():
                vulnerabilities = parse_nuclei_jsonl(raw_nuclei_path)
                save_vulnerabilities_json(
                    vulnerabilities,
                    parsed_vulnerabilities_path,
                )
                _mark_tool_completed(metadata, "nuclei")
                write_scan_metadata(scan_folder, metadata)

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
            ):
                continue
            if gowitness_result.exit_code == 0:
                gowitness_targets = load_gowitness_targets(parsed_live_hosts_path)
                screenshots = collect_screenshot_metadata(
                    gowitness_targets,
                    screenshots_dir,
                )
                save_screenshots_json(screenshots, parsed_screenshots_path)
                _mark_tool_completed(metadata, "gowitness")
                write_scan_metadata(scan_folder, metadata)

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
