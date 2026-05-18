from pathlib import Path
from tempfile import TemporaryDirectory

from reconflow.tools.nuclei import (
    build_nuclei_command,
    load_nuclei_targets,
    parse_nuclei_jsonl,
    save_vulnerabilities_json,
    write_nuclei_input,
)


SAMPLE_LIVE_HOSTS_JSON = """[
  {
    "url": "https://example.com",
    "host": "example.com",
    "status_code": 200,
    "source_tool": "httpx"
  },
  {
    "url": "https://admin.example.com",
    "host": "admin.example.com",
    "status_code": 200,
    "source_tool": "httpx"
  }
]
"""

SAMPLE_NUCLEI_JSONL = """{"template-id":"tech-detect","host":"https://example.com","matched-at":"https://example.com","info":{"name":"Technology Detection","severity":"info","description":"Detected web technology","tags":["tech","fingerprint"]},"matcher-name":"wordpress"}
{"template-id":"missing-security-header","host":"https://admin.example.com","matched-at":"https://admin.example.com/login","info":{"name":"Missing Security Header","severity":"medium","tags":"headers,misconfig"},"matched-line":"X-Frame-Options missing"}
{"template-id":"critical-panel","host":"https://admin.example.com","matched-at":"https://admin.example.com/admin","info":{"name":"Exposed Admin Panel","severity":"critical","description":"Admin panel exposed"},"extracted-results":["/admin"]}
"""


def test_load_nuclei_targets_from_live_hosts() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        live_hosts_path = Path(tmp_dir) / "live_hosts.json"
        live_hosts_path.write_text(SAMPLE_LIVE_HOSTS_JSON, encoding="utf-8")

        targets = load_nuclei_targets(live_hosts_path)

    assert targets == ["https://example.com", "https://admin.example.com"]


def test_write_nuclei_input() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        input_path = Path(tmp_dir) / "raw" / "nuclei_input.txt"

        saved_path = write_nuclei_input(
            ["https://example.com", "https://admin.example.com"],
            input_path,
        )
        saved_text = input_path.read_text(encoding="utf-8")

    assert saved_path == input_path
    assert saved_text == "https://example.com\nhttps://admin.example.com\n"


def test_build_nuclei_command_uses_safe_defaults() -> None:
    command = build_nuclei_command(
        "scans/scan_001/raw/nuclei_input.txt",
        "scans/scan_001/raw/nuclei.jsonl",
    )

    assert command == [
        "nuclei",
        "-jsonl",
        "-silent",
        "-l",
        "scans/scan_001/raw/nuclei_input.txt",
        "-o",
        "scans/scan_001/raw/nuclei.jsonl",
        "-severity",
        "info,low,medium,high,critical",
        "-exclude-tags",
        "intrusive,brute-force,bruteforce,destructive,dos,fuzz,fuzzing",
        "-rl",
        "25",
        "-c",
        "10",
        "-retries",
        "1",
        "-timeout",
        "5",
    ]


def test_parse_nuclei_jsonl_fixture() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        jsonl_path = Path(tmp_dir) / "nuclei.jsonl"
        jsonl_path.write_text(SAMPLE_NUCLEI_JSONL, encoding="utf-8")

        vulnerabilities = parse_nuclei_jsonl(jsonl_path)

    assert len(vulnerabilities) == 3
    assert vulnerabilities[0].name == "Technology Detection"
    assert vulnerabilities[0].template_id == "tech-detect"
    assert vulnerabilities[0].severity == "info"
    assert vulnerabilities[0].matched_url == "https://example.com"
    assert vulnerabilities[0].host == "https://example.com"
    assert vulnerabilities[0].description == "Detected web technology"
    assert vulnerabilities[0].tags == ["tech", "fingerprint"]
    assert vulnerabilities[0].evidence == {"matcher-name": "wordpress"}
    assert vulnerabilities[0].source_tool == "nuclei"
    assert vulnerabilities[1].severity == "medium"
    assert vulnerabilities[1].tags == ["headers", "misconfig"]
    assert vulnerabilities[1].evidence == {"matched-line": "X-Frame-Options missing"}
    assert vulnerabilities[2].severity == "critical"
    assert vulnerabilities[2].evidence == {"extracted-results": ["/admin"]}


def test_save_vulnerabilities_json() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        temp_path = Path(tmp_dir)
        jsonl_path = temp_path / "nuclei.jsonl"
        vulnerabilities_path = temp_path / "parsed" / "vulnerabilities.json"
        jsonl_path.write_text(SAMPLE_NUCLEI_JSONL, encoding="utf-8")

        vulnerabilities = parse_nuclei_jsonl(jsonl_path)
        saved_path = save_vulnerabilities_json(vulnerabilities, vulnerabilities_path)
        saved_text = vulnerabilities_path.read_text(encoding="utf-8")

    assert saved_path == vulnerabilities_path
    assert '"template_id": "tech-detect"' in saved_text
    assert '"source_tool": "nuclei"' in saved_text
