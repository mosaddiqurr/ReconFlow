import json
from pathlib import Path
from tempfile import TemporaryDirectory

from typer.testing import CliRunner

from reconflow.cli import app
from reconflow.core.storage import create_scan_folder, read_scan_metadata
from reconflow.reports.json_report import generate_reports


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


def test_generate_all_reports_from_sample_parsed_data() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        temp_path = Path(tmp_dir)
        metadata = create_scan_folder(
            target="review.example.com",
            target_type="domain",
            mode="standard",
            base_dir=temp_path / "scans",
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

    assert "# ReconFlow Report" in markdown_text
    assert "## 1. Executive Summary" in markdown_text
    assert "## 11. Prioritized Findings" in markdown_text
    assert "No vulnerability findings were parsed." in markdown_text
    assert "<h2>1. Executive Summary</h2>" in html_text
    assert json_payload["overall_risk_score"] == 60
    assert json_payload["prioritized_findings"][0]["title"] == (
        "Public admin/login surface"
    )
    assert set(updated_metadata["reports_generated"]) == {"markdown", "html", "json"}


def test_report_command_generates_requested_json_format(monkeypatch) -> None:
    original_cwd = Path.cwd()
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        temp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(temp_path)
            metadata = create_scan_folder(
                target="review.example.com",
                target_type="domain",
                mode="standard",
                base_dir=temp_path / "scans",
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
    assert report_payload["scan_id"] == "scan_001_review_example_com"
