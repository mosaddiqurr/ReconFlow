import json
from pathlib import Path
from tempfile import TemporaryDirectory

from typer.testing import CliRunner

from reconflow.cli import app
from reconflow.core.comparator import compare_scans
from reconflow.core.storage import create_scan_folder


runner = CliRunner()


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_baseline_scan(scan_path: Path) -> None:
    parsed_path = scan_path / "parsed"
    _write_json(parsed_path / "subdomains.json", ["www.example.com", "old.example.com"])
    _write_json(
        parsed_path / "live_hosts.json",
        [
            {"url": "https://www.example.com", "host": "www.example.com"},
            {"url": "https://old.example.com", "host": "old.example.com"},
        ],
    )
    _write_json(
        parsed_path / "services.json",
        [
            {
                "host": "93.184.216.34",
                "port": 80,
                "protocol": "tcp",
                "service_name": "http",
            },
            {
                "host": "93.184.216.34",
                "port": 5432,
                "protocol": "tcp",
                "service_name": "postgresql",
            },
        ],
    )
    _write_json(
        parsed_path / "technologies.json",
        [
            {
                "host": "www.example.com",
                "url": "https://www.example.com",
                "name": "nginx",
                "version": "1.24",
            },
            {
                "host": "old.example.com",
                "url": "https://old.example.com",
                "name": "php",
            },
        ],
    )
    _write_json(
        parsed_path / "endpoints.json",
        [
            {
                "url": "https://www.example.com/login",
                "host": "www.example.com",
                "path": "/login",
                "interesting": True,
            },
            {
                "url": "https://old.example.com/old",
                "host": "old.example.com",
                "path": "/old",
                "interesting": True,
            },
        ],
    )
    _write_json(
        parsed_path / "vulnerabilities.json",
        [
            {
                "template_id": "fixture-resolved-observation",
                "severity": "low",
                "matched_url": "https://old.example.com/old",
                "host": "https://old.example.com",
                "name": "Resolved test fixture observation",
            }
        ],
    )
    _write_json(
        parsed_path / "findings.json",
        {
            "overall_risk_score": 35,
            "findings": [
                {
                    "title": "Resolved correlated fixture finding",
                    "severity": "low",
                    "risk_score": 35,
                    "affected_host": "old.example.com",
                    "affected_url": "https://old.example.com/old",
                    "evidence": ["Test fixture evidence"],
                    "source_tools": ["fixture"],
                    "recommendation": "Fixture recommendation.",
                }
            ],
        },
    )


def _write_current_scan(scan_path: Path) -> None:
    parsed_path = scan_path / "parsed"
    _write_json(parsed_path / "subdomains.json", ["www.example.com", "api.example.com"])
    _write_json(
        parsed_path / "live_hosts.json",
        [
            {"url": "https://www.example.com", "host": "www.example.com"},
            {"url": "https://api.example.com", "host": "api.example.com"},
        ],
    )
    _write_json(
        parsed_path / "services.json",
        [
            {
                "host": "93.184.216.34",
                "port": 80,
                "protocol": "tcp",
                "service_name": "http",
            },
            {
                "host": "93.184.216.34",
                "port": 443,
                "protocol": "tcp",
                "service_name": "https",
            },
            {
                "host": "93.184.216.34",
                "port": 3306,
                "protocol": "tcp",
                "service_name": "mysql",
            },
        ],
    )
    _write_json(
        parsed_path / "technologies.json",
        [
            {
                "host": "www.example.com",
                "url": "https://www.example.com",
                "name": "nginx",
                "version": "1.25",
            },
            {
                "host": "api.example.com",
                "url": "https://api.example.com",
                "name": "node.js",
            },
        ],
    )
    _write_json(
        parsed_path / "endpoints.json",
        [
            {
                "url": "https://www.example.com/login",
                "host": "www.example.com",
                "path": "/login",
                "interesting": True,
            },
            {
                "url": "https://api.example.com/api/users",
                "host": "api.example.com",
                "path": "/api/users",
                "interesting": True,
            },
        ],
    )
    _write_json(
        parsed_path / "vulnerabilities.json",
        [
            {
                "template_id": "fixture-new-observation",
                "severity": "medium",
                "matched_url": "https://api.example.com/api/users",
                "host": "https://api.example.com",
                "name": "New test fixture observation",
            }
        ],
    )
    _write_json(
        parsed_path / "findings.json",
        {
            "overall_risk_score": 60,
            "findings": [
                {
                    "title": "New correlated fixture finding",
                    "severity": "medium",
                    "risk_score": 60,
                    "affected_host": "api.example.com",
                    "affected_url": "https://api.example.com/api/users",
                    "evidence": ["Test fixture evidence"],
                    "source_tools": ["fixture"],
                    "recommendation": "Fixture recommendation.",
                }
            ],
        },
    )


def _create_sample_scan_pair(base_path: Path) -> tuple[Path, Path, str, str]:
    first_metadata = create_scan_folder(
        target="example.com",
        target_type="domain",
        mode="standard",
        base_dir=base_path / "scans",
        tools_planned=["subfinder", "httpx"],
    )
    second_metadata = create_scan_folder(
        target="example.com",
        target_type="domain",
        mode="standard",
        base_dir=base_path / "scans",
        tools_planned=["subfinder", "httpx"],
    )
    first_scan_path = Path(first_metadata["output_dir"])
    second_scan_path = Path(second_metadata["output_dir"])
    _write_baseline_scan(first_scan_path)
    _write_current_scan(second_scan_path)
    return (
        first_scan_path,
        second_scan_path,
        first_metadata["scan_id"],
        second_metadata["scan_id"],
    )


def test_compare_scans_from_parsed_json_files() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        first_scan_path, second_scan_path, first_scan_id, second_scan_id = (
            _create_sample_scan_pair(temp_path)
        )

        comparison = compare_scans(
            first_scan_path,
            second_scan_path,
            first_scan_id,
            second_scan_id,
            output_base_dir=temp_path / "scans",
        )
        output_path = Path(comparison["output_path"])
        saved_payload = json.loads(output_path.read_text(encoding="utf-8"))

        assert output_path.exists()

    assert comparison["new_subdomains"] == ["api.example.com"]
    assert comparison["removed_subdomains"] == ["old.example.com"]
    assert comparison["new_live_hosts"] == ["https://api.example.com"]
    assert comparison["removed_live_hosts"] == ["https://old.example.com"]
    assert comparison["new_open_ports"] == [
        "93.184.216.34:3306/tcp mysql",
        "93.184.216.34:443/tcp https",
    ]
    assert comparison["closed_ports"] == ["93.184.216.34:5432/tcp postgresql"]
    assert comparison["new_technologies"] == [
        "api.example.com node.js",
        "www.example.com nginx 1.25",
    ]
    assert comparison["removed_technologies"] == [
        "old.example.com php",
        "www.example.com nginx 1.24",
    ]
    assert comparison["new_endpoints"] == ["https://api.example.com/api/users"]
    assert comparison["removed_endpoints"] == ["https://old.example.com/old"]
    assert comparison["new_vulnerabilities"] == [
        (
            "fixture-new-observation|medium|"
            "https://api.example.com/api/users|new test fixture observation"
        )
    ]
    assert comparison["resolved_vulnerabilities"] == [
        (
            "fixture-resolved-observation|low|"
            "https://old.example.com/old|resolved test fixture observation"
        )
    ]
    assert comparison["new_correlated_findings"] == [
        (
            "new correlated fixture finding|medium|api.example.com|"
            "https://api.example.com/api/users"
        )
    ]
    assert comparison["resolved_correlated_findings"] == [
        (
            "resolved correlated fixture finding|low|old.example.com|"
            "https://old.example.com/old"
        )
    ]
    assert saved_payload["scan_id_1"] == first_scan_id
    assert saved_payload["scan_id_2"] == second_scan_id


def test_compare_command_writes_comparison_json(monkeypatch) -> None:
    original_cwd = Path.cwd()
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        try:
            monkeypatch.chdir(temp_path)
            _, _, first_scan_id, second_scan_id = _create_sample_scan_pair(temp_path)

            result = runner.invoke(app, ["compare", first_scan_id, second_scan_id])
            comparison_path = (
                temp_path
                / "scans"
                / "comparisons"
                / f"{first_scan_id}_vs_{second_scan_id}.json"
            )
            payload = json.loads(comparison_path.read_text(encoding="utf-8"))
            assert comparison_path.exists()
        finally:
            monkeypatch.chdir(original_cwd)

    assert result.exit_code == 0
    assert "ReconFlow Scan Comparison" in result.output
    assert "Comparison Details" in result.output
    assert payload["new_subdomains"] == ["api.example.com"]
