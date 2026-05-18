from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from reconflow.tools.whatweb import (
    build_whatweb_command,
    load_whatweb_targets,
    parse_whatweb_json,
    save_technologies_json,
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

SAMPLE_WHATWEB_JSON = """[
  {
    "target": "https://example.com",
    "plugins": {
      "nginx": {
        "version": ["1.24.0"],
        "categories": ["Web servers"]
      },
      "jQuery": {
        "version": ["3.7.1"],
        "categories": ["JavaScript libraries"]
      }
    }
  },
  {
    "target": "https://admin.example.com",
    "plugins": {
      "PHP": {
        "version": ["8.2"],
        "category": "Programming languages"
      }
    }
  }
]
"""


def test_load_whatweb_targets_from_live_hosts() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        live_hosts_path = Path(tmp_dir) / "live_hosts.json"
        live_hosts_path.write_text(SAMPLE_LIVE_HOSTS_JSON, encoding="utf-8")

        targets = load_whatweb_targets(live_hosts_path)

    assert targets == ["https://example.com", "https://admin.example.com"]


def test_build_whatweb_command() -> None:
    command = build_whatweb_command(
        ["https://example.com", "https://admin.example.com"],
        "scans/scan_001/raw/whatweb.json",
    )

    assert command == [
        "whatweb",
        "--log-json",
        "scans/scan_001/raw/whatweb.json",
        "https://example.com",
        "https://admin.example.com",
    ]


def test_build_whatweb_command_requires_targets() -> None:
    with pytest.raises(ValueError):
        build_whatweb_command([], "whatweb.json")


def test_parse_whatweb_json_fixture() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        output_path = Path(tmp_dir) / "whatweb.json"
        output_path.write_text(SAMPLE_WHATWEB_JSON, encoding="utf-8")

        technologies = parse_whatweb_json(output_path)

    assert len(technologies) == 3
    assert technologies[0].host == "example.com"
    assert technologies[0].url == "https://example.com"
    assert technologies[0].name == "nginx"
    assert technologies[0].version == "1.24.0"
    assert technologies[0].category == "Web servers"
    assert technologies[0].source_tool == "whatweb"
    assert technologies[1].name == "jQuery"
    assert technologies[2].host == "admin.example.com"
    assert technologies[2].name == "PHP"
    assert technologies[2].version == "8.2"


def test_save_technologies_json() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        temp_path = Path(tmp_dir)
        output_path = temp_path / "whatweb.json"
        technologies_path = temp_path / "parsed" / "technologies.json"
        output_path.write_text(SAMPLE_WHATWEB_JSON, encoding="utf-8")

        technologies = parse_whatweb_json(output_path)
        saved_path = save_technologies_json(technologies, technologies_path)
        saved_text = technologies_path.read_text(encoding="utf-8")

    assert saved_path == technologies_path
    assert '"name": "nginx"' in saved_text
    assert '"source_tool": "whatweb"' in saved_text
