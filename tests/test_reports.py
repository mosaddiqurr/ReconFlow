import json
from pathlib import Path

from typer.testing import CliRunner

from reconflow.cli import app
from reconflow.core.storage import create_scan_folder, read_scan_metadata, write_scan_metadata
from reconflow.reports.json_report import (
    generate_all_report_views,
    generate_reports,
)


runner = CliRunner()


def _write_sample_parsed_data(scan_path: Path) -> None:
    parsed_path = scan_path / "parsed"
    (parsed_path / "assets.json").write_text(
        json.dumps(
            [
                {
                    "hostname": "review.example.com",
                    "ip": "93.184.216.34",
                    "record_type": "A",
                    "source_tool": "dnsx",
                    "is_resolved": True,
                }
            ]
        ),
        encoding="utf-8",
    )
    (parsed_path / "live_hosts.json").write_text(
        json.dumps(
            [
                {
                    "url": "https://review.example.com",
                    "host": "review.example.com",
                    "status_code": 200,
                    "title": "Review Site",
                    "source_tool": "httpx",
                }
            ]
        ),
        encoding="utf-8",
    )
    (parsed_path / "services.json").write_text(
        json.dumps(
            [
                {
                    "host": "93.184.216.34",
                    "port": 443,
                    "protocol": "tcp",
                    "service_name": "https",
                    "product": "nginx",
                    "state": "open",
                    "source_tool": "nmap",
                }
            ]
        ),
        encoding="utf-8",
    )
    (parsed_path / "technologies.json").write_text(
        json.dumps(
            [
                {
                    "host": "review.example.com",
                    "url": "https://review.example.com",
                    "name": "nginx",
                    "version": "1.24",
                    "category": "web server",
                    "source_tool": "whatweb",
                }
            ]
        ),
        encoding="utf-8",
    )
    (parsed_path / "endpoints.json").write_text(
        json.dumps(
            [
                {
                    "url": "https://review.example.com/login",
                    "host": "review.example.com",
                    "path": "/login",
                    "status_code": 200,
                    "source_tool": "feroxbuster",
                    "interesting": True,
                }
            ]
        ),
        encoding="utf-8",
    )
    (parsed_path / "vulnerabilities.json").write_text("[]\n", encoding="utf-8")
    (parsed_path / "findings.json").write_text(
        json.dumps(
            {
                "overall_risk_score": 60,
                "findings": [
                    {
                        "title": "Public admin/login surface",
                        "severity": "medium",
                        "risk_score": 60,
                        "affected_host": "review.example.com",
                        "affected_url": "https://review.example.com/login",
                        "evidence": ["Public endpoint /login was discovered"],
                        "source_tools": ["feroxbuster"],
                        "recommendation": "Review authentication controls for this endpoint.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_generate_all_reports_from_sample_parsed_data(tmp_path) -> None:
    metadata = create_scan_folder(
        target="review.example.com",
        target_type="domain",
        mode="standard",
        base_dir=tmp_path / "scans",
        tools_planned=["nmap", "httpx", "feroxbuster"],
    )
    scan_path = Path(metadata["output_dir"])
    _write_sample_parsed_data(scan_path)

    generated = generate_reports(scan_path, "all")
    markdown_text = generated["markdown"].read_text(encoding="utf-8")
    html_text = generated["html"].read_text(encoding="utf-8")
    json_payload = json.loads(generated["json"].read_text(encoding="utf-8"))
    updated_metadata = read_scan_metadata(scan_path / "metadata.json")

    assert generated["markdown"].exists()
    assert generated["html"].exists()
    assert generated["json"].exists()
    assert "# ReconFlow Summary Report" in markdown_text
    assert "## Scan Overview" in markdown_text
    assert "## Key Findings" in markdown_text
    assert "## Correlated Risk Findings" in markdown_text
    assert "<h2>Scan Overview</h2>" in html_text
    assert json_payload["view"] == "summary"
    assert json_payload["scan_overview"]["overall_risk_score"] == 60
    assert json_payload["correlated_findings"][0]["title"] == (
        "Public admin/login surface"
    )
    assert "summary" in updated_metadata["reports_generated"]


def test_report_command_generates_requested_json_format(monkeypatch, tmp_path) -> None:
    original_cwd = Path.cwd()
    try:
        monkeypatch.chdir(tmp_path)
        metadata = create_scan_folder(
            target="review.example.com",
            target_type="domain",
            mode="standard",
            base_dir=tmp_path / "scans",
            tools_planned=["nmap", "httpx"],
        )
        scan_path = Path(metadata["output_dir"])
        _write_sample_parsed_data(scan_path)

        result = runner.invoke(
            app,
            ["report", "scan_001_review_example_com", "--format", "json"],
        )
        report_path = scan_path / "reports" / "report.json"
        assert report_path.exists()
        report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    finally:
        monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "Generated json report" in result.output
    assert report_payload["view"] == "summary"
    assert report_payload["scan_id"] == "scan_001_review_example_com"


def test_report_command_view_raw_creates_raw_report_files(monkeypatch, tmp_path) -> None:
    original_cwd = Path.cwd()
    try:
        monkeypatch.chdir(tmp_path)
        metadata = create_scan_folder(
            target="review.example.com",
            target_type="domain",
            mode="standard",
            base_dir=tmp_path / "scans",
            tools_planned=["nmap", "httpx", "feroxbuster"],
        )
        scan_path = Path(metadata["output_dir"])
        _write_sample_parsed_data(scan_path)

        result = runner.invoke(
            app,
            [
                "report",
                "scan_001_review_example_com",
                "--format",
                "all",
                "--view",
                "raw",
            ],
        )
    finally:
        monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "raw view" in result.output
    assert (scan_path / "reports" / "report_raw.md").exists()
    assert (scan_path / "reports" / "report_raw.html").exists()
    assert (scan_path / "reports" / "report_raw.json").exists()


def test_report_command_view_summary_creates_summary_and_compat_files(
    monkeypatch,
    tmp_path,
) -> None:
    original_cwd = Path.cwd()
    try:
        monkeypatch.chdir(tmp_path)
        metadata = create_scan_folder(
            target="review.example.com",
            target_type="domain",
            mode="standard",
            base_dir=tmp_path / "scans",
            tools_planned=["nmap", "httpx", "feroxbuster"],
        )
        scan_path = Path(metadata["output_dir"])
        _write_sample_parsed_data(scan_path)

        result = runner.invoke(
            app,
            [
                "report",
                "scan_001_review_example_com",
                "--format",
                "all",
                "--view",
                "summary",
            ],
        )
    finally:
        monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "summary view" in result.output
    assert (scan_path / "reports" / "report_summary.md").exists()
    assert (scan_path / "reports" / "report_summary.html").exists()
    assert (scan_path / "reports" / "report_summary.json").exists()
    assert (scan_path / "reports" / "report.md").exists()
    assert (scan_path / "reports" / "report.html").exists()
    assert (scan_path / "reports" / "report.json").exists()


def test_scan_report_generation_creates_both_views_and_compat_files(tmp_path) -> None:
    metadata = create_scan_folder(
        target="review.example.com",
        target_type="domain",
        mode="standard",
        base_dir=tmp_path / "scans",
        tools_planned=["nmap", "httpx", "feroxbuster"],
    )
    scan_path = Path(metadata["output_dir"])
    _write_sample_parsed_data(scan_path)

    generated = generate_all_report_views(scan_path)

    assert generated["raw"]["markdown"].name == "report_raw.md"
    assert generated["summary"]["markdown"].name == "report_summary.md"
    assert (scan_path / "reports" / "report.md").exists()
    assert (scan_path / "reports" / "report.html").exists()
    assert (scan_path / "reports" / "report.json").exists()


def test_summary_report_omits_empty_noisy_sections(tmp_path) -> None:
    metadata = create_scan_folder(
        target="quiet.example.com",
        target_type="domain",
        mode="standard",
        base_dir=tmp_path / "scans",
        tools_planned=["nmap", "httpx", "nuclei"],
    )
    scan_path = Path(metadata["output_dir"])
    (scan_path / "parsed" / "findings.json").write_text(
        json.dumps({"overall_risk_score": 0, "findings": []}),
        encoding="utf-8",
    )

    generated = generate_reports(scan_path, "markdown", view="summary")
    summary_text = generated["markdown"].read_text(encoding="utf-8")

    assert "## Scan Overview" in summary_text
    assert "## Key Findings" not in summary_text
    assert "## Security-Relevant Observations" not in summary_text
    assert "## Vulnerability Summary" not in summary_text
    assert "## Correlated Risk Findings" not in summary_text
    assert "No major security-relevant findings were identified" in summary_text


def test_summary_report_only_includes_non_zero_findings(tmp_path) -> None:
    metadata = create_scan_folder(
        target="review.example.com",
        target_type="domain",
        mode="standard",
        base_dir=tmp_path / "scans",
        tools_planned=["nmap", "httpx", "feroxbuster"],
    )
    scan_path = Path(metadata["output_dir"])
    _write_sample_parsed_data(scan_path)

    generated = generate_reports(scan_path, "markdown", view="summary")
    summary_text = generated["markdown"].read_text(encoding="utf-8")

    assert "1 open service was discovered." in summary_text
    assert "1 live web application was detected." in summary_text
    assert "1 endpoint was discovered." in summary_text
    assert "0 vulnerability" not in summary_text


def test_raw_report_includes_tool_by_tool_sections(tmp_path) -> None:
    metadata = create_scan_folder(
        target="review.example.com",
        target_type="domain",
        mode="standard",
        base_dir=tmp_path / "scans",
        tools_planned=["nmap", "httpx", "feroxbuster"],
    )
    scan_path = Path(metadata["output_dir"])
    _write_sample_parsed_data(scan_path)

    generated = generate_reports(scan_path, "markdown", view="raw")
    raw_text = generated["markdown"].read_text(encoding="utf-8")

    assert "# ReconFlow Raw Report" in raw_text
    assert "## Tool Results" in raw_text
    assert "### Tool 1: nmap" in raw_text
    assert "### Tool 2: httpx" in raw_text
    assert "### Tool 3: feroxbuster" in raw_text


def test_backward_compatible_report_files_match_summary_output(tmp_path) -> None:
    metadata = create_scan_folder(
        target="review.example.com",
        target_type="domain",
        mode="standard",
        base_dir=tmp_path / "scans",
        tools_planned=["nmap", "httpx", "feroxbuster"],
    )
    scan_path = Path(metadata["output_dir"])
    _write_sample_parsed_data(scan_path)

    generate_reports(scan_path, "all", view="summary")

    assert (scan_path / "reports" / "report.md").read_text(encoding="utf-8") == (
        scan_path / "reports" / "report_summary.md"
    ).read_text(encoding="utf-8")
    assert (scan_path / "reports" / "report.html").read_text(encoding="utf-8") == (
        scan_path / "reports" / "report_summary.html"
    ).read_text(encoding="utf-8")
    assert json.loads((scan_path / "reports" / "report.json").read_text(encoding="utf-8")) == json.loads(
        (scan_path / "reports" / "report_summary.json").read_text(encoding="utf-8")
    )


def test_summary_recommended_actions_are_based_on_actual_findings(tmp_path) -> None:
    metadata = create_scan_folder(
        target="review.example.com",
        target_type="domain",
        mode="standard",
        base_dir=tmp_path / "scans",
        tools_planned=["nmap", "httpx", "feroxbuster"],
    )
    scan_path = Path(metadata["output_dir"])
    _write_sample_parsed_data(scan_path)

    generated = generate_reports(scan_path, "json", view="summary")
    payload = json.loads(generated["json"].read_text(encoding="utf-8"))

    assert "Review exposed web services on ports 443." in payload[
        "recommended_actions"
    ]
    assert "Validate whether discovered endpoints should be publicly accessible." in payload[
        "recommended_actions"
    ]
    assert "Review authentication controls for this endpoint." in payload[
        "recommended_actions"
    ]


def test_missing_tools_stay_in_tool_execution_summary(tmp_path) -> None:
    metadata = create_scan_folder(
        target="review.example.com",
        target_type="domain",
        mode="standard",
        base_dir=tmp_path / "scans",
        tools_planned=["httpx", "nuclei"],
    )
    metadata["tools_completed"] = ["httpx"]
    metadata["tools_skipped"] = [{"tool": "nuclei", "reason": "Missing external tool"}]
    scan_path = Path(metadata["output_dir"])
    write_scan_metadata(scan_path, metadata)
    (scan_path / "parsed" / "live_hosts.json").write_text(
        json.dumps(
            [
                {
                    "url": "https://review.example.com",
                    "host": "review.example.com",
                    "status_code": 200,
                    "source_tool": "httpx",
                }
            ]
        ),
        encoding="utf-8",
    )
    (scan_path / "parsed" / "findings.json").write_text(
        json.dumps({"overall_risk_score": 0, "findings": []}),
        encoding="utf-8",
    )

    generated = generate_reports(scan_path, "json", view="summary")
    payload = json.loads(generated["json"].read_text(encoding="utf-8"))

    assert payload["tool_execution_summary"]["missing_tools"] == ["nuclei"]
    assert all(
        "nuclei" not in observation["detail"].lower()
        for observation in payload["security_observations"]
    )
