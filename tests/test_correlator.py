import json
from pathlib import Path
from tempfile import TemporaryDirectory

from reconflow.core.correlator import correlate_scan
from reconflow.core.scorer import calculate_overall_risk_score, score_for_rule


def test_correlate_scan_creates_findings_from_fake_parsed_data() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        scan_path = Path(tmp_dir) / "scan_001_example_com"
        parsed_path = scan_path / "parsed"
        parsed_path.mkdir(parents=True)

        (parsed_path / "assets.json").write_text(
            json.dumps(
                [
                    {
                        "hostname": "staging.example.com",
                        "ip": "93.184.216.34",
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
                        "url": "https://staging.example.com",
                        "host": "staging.example.com",
                        "status_code": 200,
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
                        "port": 22,
                        "service_name": "ssh",
                        "state": "open",
                        "source_tool": "nmap",
                    },
                    {
                        "host": "93.184.216.34",
                        "port": 80,
                        "service_name": "http",
                        "state": "open",
                        "source_tool": "nmap",
                    },
                    {
                        "host": "93.184.216.34",
                        "port": 3306,
                        "service_name": "mysql",
                        "state": "open",
                        "source_tool": "nmap",
                    },
                ]
            ),
            encoding="utf-8",
        )
        (parsed_path / "endpoints.json").write_text(
            json.dumps(
                [
                    {
                        "url": "https://staging.example.com/login",
                        "host": "staging.example.com",
                        "path": "/login",
                        "status_code": 200,
                        "source_tool": "feroxbuster",
                        "interesting": True,
                    },
                    {
                        "url": "https://staging.example.com/wp-admin/",
                        "host": "staging.example.com",
                        "path": "/wp-admin/",
                        "status_code": 200,
                        "source_tool": "feroxbuster",
                        "interesting": True,
                    },
                    {
                        "url": "https://staging.example.com/backup.zip",
                        "host": "staging.example.com",
                        "path": "/backup.zip",
                        "status_code": 200,
                        "source_tool": "feroxbuster",
                        "interesting": True,
                    },
                ]
            ),
            encoding="utf-8",
        )
        (parsed_path / "technologies.json").write_text(
            json.dumps(
                [
                    {
                        "host": "staging.example.com",
                        "url": "https://staging.example.com",
                        "name": "WordPress",
                        "source_tool": "whatweb",
                    }
                ]
            ),
            encoding="utf-8",
        )
        (parsed_path / "crawled_urls.json").write_text(
            json.dumps(
                [
                    {
                        "url": "https://staging.example.com/api/users?token=abc",
                        "host": "staging.example.com",
                        "path": "/api/users",
                        "query_params": {"token": ["abc"]},
                        "source_tool": "katana",
                    }
                ]
            ),
            encoding="utf-8",
        )
        (parsed_path / "vulnerabilities.json").write_text(
            json.dumps(
                [
                    {
                        "name": "Critical Admin Exposure",
                        "template_id": "critical-admin",
                        "severity": "critical",
                        "matched_url": "https://staging.example.com/admin",
                        "host": "https://staging.example.com",
                        "description": "Admin exposure",
                        "tags": ["exposure"],
                        "evidence": {"matcher-name": "admin"},
                        "source_tool": "nuclei",
                    }
                ]
            ),
            encoding="utf-8",
        )

        result = correlate_scan(scan_path)
        output_payload = json.loads(result.output_path.read_text(encoding="utf-8"))

        assert result.output_path.exists()

    titles = {finding.title for finding in result.findings}
    assert "Public admin/login surface" in titles
    assert "WordPress admin surface" in titles
    assert "Development or staging host" in titles
    assert "Exposed backup/config file" in titles
    assert "Open database/service port" in titles
    assert "Interesting endpoint discovered" in titles
    assert "Multiple exposed services on one host" in titles
    assert "Nuclei high or critical finding: Critical Admin Exposure" in titles
    assert result.overall_risk_score == 100
    assert output_payload["overall_risk_score"] == 100
    assert len(output_payload["findings"]) == len(result.findings)


def test_scoring_uses_risk_rules_and_bounds_overall_score() -> None:
    assert score_for_rule("exposed_backup_config_file") == 80
    assert score_for_rule("nuclei_high_or_critical_finding", "critical") == 95
    assert calculate_overall_risk_score([]) == 0
