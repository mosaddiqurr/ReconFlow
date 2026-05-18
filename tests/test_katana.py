import json
from pathlib import Path
from tempfile import TemporaryDirectory

from reconflow.tools.katana import (
    build_katana_command,
    is_interesting_crawled_url,
    load_katana_targets,
    merge_interesting_crawled_urls_into_endpoints,
    parse_katana_jsonl,
    save_crawled_urls_json,
    write_katana_input,
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

SAMPLE_KATANA_JSONL = """{"url":"https://example.com/login?redirect=/dashboard"}
{"request":{"endpoint":"https://example.com/assets/app.js"}}
{"url":"https://example.com/api/users?token=abc"}
{"url":"https://example.com/login?redirect=/dashboard"}
"""


def test_load_katana_targets_from_live_hosts() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        live_hosts_path = Path(tmp_dir) / "live_hosts.json"
        live_hosts_path.write_text(SAMPLE_LIVE_HOSTS_JSON, encoding="utf-8")

        targets = load_katana_targets(live_hosts_path)

    assert targets == ["https://example.com", "https://admin.example.com"]


def test_write_katana_input() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        input_path = Path(tmp_dir) / "raw" / "katana_input.txt"

        saved_path = write_katana_input(
            ["https://example.com", "https://admin.example.com"],
            input_path,
        )
        saved_text = input_path.read_text(encoding="utf-8")

    assert saved_path == input_path
    assert saved_text == "https://example.com\nhttps://admin.example.com\n"


def test_build_katana_command() -> None:
    command = build_katana_command(
        "scans/scan_001/raw/katana_input.txt",
        "scans/scan_001/raw/katana.jsonl",
    )

    assert command == [
        "katana",
        "-jsonl",
        "-silent",
        "-d",
        "2",
        "-list",
        "scans/scan_001/raw/katana_input.txt",
        "-o",
        "scans/scan_001/raw/katana.jsonl",
    ]


def test_parse_katana_jsonl_fixture() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        jsonl_path = Path(tmp_dir) / "katana.jsonl"
        jsonl_path.write_text(SAMPLE_KATANA_JSONL, encoding="utf-8")

        crawled_urls = parse_katana_jsonl(jsonl_path)

    assert len(crawled_urls) == 3
    assert crawled_urls[0].url == "https://example.com/login?redirect=/dashboard"
    assert crawled_urls[0].host == "example.com"
    assert crawled_urls[0].path == "/login"
    assert crawled_urls[0].query_params == {"redirect": ["/dashboard"]}
    assert crawled_urls[0].source_tool == "katana"
    assert crawled_urls[1].path == "/assets/app.js"
    assert crawled_urls[2].query_params == {"token": ["abc"]}


def test_interesting_crawled_url_markers() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        jsonl_path = Path(tmp_dir) / "katana.jsonl"
        jsonl_path.write_text(SAMPLE_KATANA_JSONL, encoding="utf-8")

        crawled_urls = parse_katana_jsonl(jsonl_path)

    assert is_interesting_crawled_url(crawled_urls[0])
    assert not is_interesting_crawled_url(crawled_urls[1])
    assert is_interesting_crawled_url(crawled_urls[2])


def test_save_crawled_urls_json() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        temp_path = Path(tmp_dir)
        jsonl_path = temp_path / "katana.jsonl"
        crawled_urls_path = temp_path / "parsed" / "crawled_urls.json"
        jsonl_path.write_text(SAMPLE_KATANA_JSONL, encoding="utf-8")

        crawled_urls = parse_katana_jsonl(jsonl_path)
        saved_path = save_crawled_urls_json(crawled_urls, crawled_urls_path)
        saved_text = crawled_urls_path.read_text(encoding="utf-8")

    assert saved_path == crawled_urls_path
    assert '"path": "/login"' in saved_text
    assert '"source_tool": "katana"' in saved_text


def test_merge_interesting_crawled_urls_into_endpoints_without_duplicates() -> None:
    with TemporaryDirectory(dir="C:\\tmp") as tmp_dir:
        temp_path = Path(tmp_dir)
        jsonl_path = temp_path / "katana.jsonl"
        endpoints_path = temp_path / "parsed" / "endpoints.json"
        jsonl_path.write_text(SAMPLE_KATANA_JSONL, encoding="utf-8")
        endpoints_path.parent.mkdir(parents=True)
        endpoints_path.write_text(
            json.dumps(
                [
                    {
                        "url": "https://example.com/login?redirect=/dashboard",
                        "host": "example.com",
                        "path": "/login",
                        "source_tool": "feroxbuster",
                        "interesting": True,
                    }
                ],
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        crawled_urls = parse_katana_jsonl(jsonl_path)
        endpoints = merge_interesting_crawled_urls_into_endpoints(
            crawled_urls,
            endpoints_path,
        )
        saved_endpoints = json.loads(endpoints_path.read_text(encoding="utf-8"))

    assert len(endpoints) == 2
    assert len(saved_endpoints) == 2
    assert saved_endpoints[0]["source_tool"] == "feroxbuster"
    assert saved_endpoints[1]["url"] == "https://example.com/api/users?token=abc"
    assert saved_endpoints[1]["source_tool"] == "katana"
    assert saved_endpoints[1]["interesting"] is True
