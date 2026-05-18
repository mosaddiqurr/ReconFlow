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
    find_scan_folder,
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
    subfinder_command = build_subfinder_command(scan_target.value, raw_subfinder_path)
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
                scan_target.value,
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
    generated_reports = {}
    if has_parsed_data(scan_folder):
        generated_reports = generate_reports(scan_folder, "all")

    table = Table(title="ReconFlow Scan Summary")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Scan ID", metadata["scan_id"])
    table.add_row("Target", scan_target.value)
    table.add_row("Detected Target Type", scan_target.kind)
    table.add_row("Selected Scan Mode", selected_mode)
    table.add_row("Authorization Status", "Authorized")
    table.add_row("Output Directory", metadata["output_dir"])
    table.add_row("Subdomains", str(len(subdomains)))
    table.add_row(
        "Parsed Subdomains Path",
        str(parsed_subdomains_path) if parsed_subdomains_path.exists() else "-",
    )
    if subfinder_result is not None:
        table.add_row("Subfinder Exit Code", str(subfinder_result.exit_code))
    table.add_row("Resolved Assets", str(len(assets)))
    table.add_row(
        "Parsed Assets Path",
        str(parsed_assets_path) if parsed_assets_path.exists() else "-",
    )
    if dnsx_result is not None:
        table.add_row("dnsx Exit Code", str(dnsx_result.exit_code))
    table.add_row("Open Ports", str(len(services)))
    table.add_row(
        "Detected Services",
        ", ".join(
            f"{service.port}/{service.protocol} {service.service_name}"
            for service in services
        )
        or "-",
    )
    table.add_row("Raw Output Path", str(raw_nmap_path))
    table.add_row(
        "Parsed Output Path",
        str(parsed_services_path) if parsed_services_path.exists() else "-",
    )
    if nmap_result is not None:
        table.add_row("Nmap Exit Code", str(nmap_result.exit_code))
    table.add_row("Live Web Services", str(len(live_hosts)))
    table.add_row(
        "Status Codes",
        ", ".join(
            str(live_host.status_code)
            for live_host in live_hosts
            if live_host.status_code is not None
        )
        or "-",
    )
    table.add_row(
        "Titles",
        ", ".join(live_host.title for live_host in live_hosts if live_host.title)
        or "-",
    )
    table.add_row("httpx Raw Output Path", str(raw_httpx_path))
    table.add_row(
        "httpx Parsed Output Path",
        str(parsed_live_hosts_path) if parsed_live_hosts_path.exists() else "-",
    )
    if httpx_result is not None:
        table.add_row("httpx Exit Code", str(httpx_result.exit_code))
    table.add_row("Technologies Detected", str(len(technologies)))
    table.add_row("Top Technologies by Host", _top_technologies_by_host(technologies))
    table.add_row(
        "Technologies Path",
        str(parsed_technologies_path) if parsed_technologies_path.exists() else "-",
    )
    if whatweb_result is not None:
        table.add_row("WhatWeb Exit Code", str(whatweb_result.exit_code))
    table.add_row("Endpoints Discovered", str(len(endpoints)))
    table.add_row(
        "Interesting Endpoints",
        str(sum(1 for endpoint in endpoints if endpoint.interesting)),
    )
    table.add_row(
        "Endpoints Path",
        str(parsed_endpoints_path) if parsed_endpoints_path.exists() else "-",
    )
    if feroxbuster_result is not None:
        table.add_row("Feroxbuster Exit Code", str(feroxbuster_result.exit_code))
    table.add_row("Crawled URLs", str(len(crawled_urls)))
    table.add_row(
        "Crawled URLs Path",
        str(parsed_crawled_urls_path) if parsed_crawled_urls_path.exists() else "-",
    )
    if katana_result is not None:
        table.add_row("Katana Exit Code", str(katana_result.exit_code))
    severity_counts = _severity_counts(vulnerabilities)
    table.add_row("Informational Findings", str(severity_counts["informational"]))
    table.add_row("Low Findings", str(severity_counts["low"]))
    table.add_row("Medium Findings", str(severity_counts["medium"]))
    table.add_row("High Findings", str(severity_counts["high"]))
    table.add_row("Critical Findings", str(severity_counts["critical"]))
    table.add_row(
        "Vulnerabilities Path",
        (
            str(parsed_vulnerabilities_path)
            if parsed_vulnerabilities_path.exists()
            else "-"
        ),
    )
    if nuclei_result is not None:
        table.add_row("Nuclei Exit Code", str(nuclei_result.exit_code))
    table.add_row(
        "Screenshots Captured",
        str(sum(1 for screenshot in screenshots if screenshot.status == "captured")),
    )
    table.add_row("Screenshot Folder", str(screenshots_dir))
    table.add_row(
        "Screenshots Path",
        str(parsed_screenshots_path) if parsed_screenshots_path.exists() else "-",
    )
    if gowitness_result is not None:
        table.add_row("Gowitness Exit Code", str(gowitness_result.exit_code))
    table.add_row("Correlated Findings", str(len(findings)))
    table.add_row("Overall Risk Score", str(overall_risk_score))
    table.add_row("Findings Path", str(parsed_findings_path))
    if generated_reports:
        table.add_row("Reports Generated", ", ".join(generated_reports))

    console.print(table)
    _print_report_paths(generated_reports)
    _print_findings_summary(findings)

    workflow_table = Table(title="Planned Workflow")
    workflow_table.add_column("Step", justify="right")
    workflow_table.add_column("Tool", style="bold")
    workflow_table.add_column("Purpose")
    for index, step in enumerate(workflow_steps, start=1):
        workflow_table.add_row(str(index), step.name, step.description)

    console.print(workflow_table)
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
        generated_reports = generate_reports(scan_folder, report_format)
    except ValueError as exc:
        _print_error_panel("Invalid Report Format", str(exc))
        raise typer.Exit(code=1) from exc

    for generated_format, path in generated_reports.items():
        console.print(
            f"Generated {generated_format} report for [bold]{scan_id}[/bold]: {path}"
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
