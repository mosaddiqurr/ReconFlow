from pathlib import Path
from tempfile import TemporaryDirectory

from reconflow.tools.dnsx import (
    build_dnsx_command,
    parse_dnsx_jsonl,
    save_assets_json,
    write_dnsx_input,
)


SAMPLE_DNSX_JSONL = """{"host":"www.example.com","a":["93.184.216.34"]}
{"host":"api.example.com","resp":[{"type":"A","data":"93.184.216.35"}]}
{"host":"missing.example.com"}
"""


def test_build_dnsx_command() -> None:
    command = build_dnsx_command(
        "scans/scan_001/raw/dnsx_input.txt",
        "scans/scan_001/raw/dnsx.jsonl",
    )

    assert command == [
        "dnsx",
        "-json",
        "-silent",
        "-l",
        "scans/scan_001/raw/dnsx_input.txt",
        "-o",
        "scans/scan_001/raw/dnsx.jsonl",
    ]


def test_write_dnsx_input() -> None:
    with TemporaryDirectory() as tmp_dir:
        input_path = Path(tmp_dir) / "raw" / "dnsx_input.txt"

        saved_path = write_dnsx_input(
            ["www.example.com", "api.example.com"],
            input_path,
        )
        saved_text = input_path.read_text(encoding="utf-8")

    assert saved_path == input_path
    assert saved_text == "www.example.com\napi.example.com\n"


def test_parse_dnsx_jsonl_fixture() -> None:
    with TemporaryDirectory() as tmp_dir:
        jsonl_path = Path(tmp_dir) / "dnsx.jsonl"
        jsonl_path.write_text(SAMPLE_DNSX_JSONL, encoding="utf-8")

        assets = parse_dnsx_jsonl(jsonl_path)

    assert len(assets) == 3
    assert assets[0].hostname == "www.example.com"
    assert assets[0].ip == "93.184.216.34"
    assert assets[0].record_type == "A"
    assert assets[0].source_tool == "dnsx"
    assert assets[0].is_resolved is True
    assert assets[1].hostname == "api.example.com"
    assert assets[1].ip == "93.184.216.35"
    assert assets[1].record_type == "A"
    assert assets[2].hostname == "missing.example.com"
    assert assets[2].ip is None
    assert assets[2].is_resolved is False


def test_parse_dnsx_jsonl_skips_malformed_line() -> None:
    warnings: list[str] = []
    with TemporaryDirectory() as tmp_dir:
        jsonl_path = Path(tmp_dir) / "dnsx.jsonl"
        jsonl_path.write_text(
            '{"host":"www.example.com","a":["93.184.216.34"]}\n'
            '{"host":"broken.example.com"\n',
            encoding="utf-8",
        )

        assets = parse_dnsx_jsonl(jsonl_path, parse_warnings=warnings)

    assert len(assets) == 1
    assert assets[0].hostname == "www.example.com"
    assert warnings == ["Skipped 1 malformed JSONL line"]


def test_save_assets_json() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        jsonl_path = temp_path / "dnsx.jsonl"
        output_path = temp_path / "parsed" / "assets.json"
        jsonl_path.write_text(SAMPLE_DNSX_JSONL, encoding="utf-8")

        assets = parse_dnsx_jsonl(jsonl_path)
        saved_path = save_assets_json(assets, output_path)
        saved_text = output_path.read_text(encoding="utf-8")

    assert saved_path == output_path
    assert '"hostname": "www.example.com"' in saved_text
    assert '"source_tool": "dnsx"' in saved_text
