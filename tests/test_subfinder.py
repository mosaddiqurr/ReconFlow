from pathlib import Path
from tempfile import TemporaryDirectory

from reconflow.tools.subfinder import (
    build_subfinder_command,
    parse_subfinder_output,
    save_subdomains_json,
    select_subfinder_domain,
)


SAMPLE_SUBFINDER_OUTPUT = """www.example.com
api.example.com
www.example.com

"""


def test_build_subfinder_command() -> None:
    command = build_subfinder_command(
        "example.com",
        "scans/scan_001/raw/subfinder.txt",
    )

    assert command == [
        "subfinder",
        "-silent",
        "-d",
        "example.com",
        "-o",
        "scans/scan_001/raw/subfinder.txt",
    ]


def test_select_subfinder_domain_strips_www_prefix_when_possible() -> None:
    assert select_subfinder_domain("www.micratto.com") == "micratto.com"
    assert select_subfinder_domain("api.micratto.com") == "api.micratto.com"


def test_parse_subfinder_output_fixture() -> None:
    with TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "subfinder.txt"
        output_path.write_text(SAMPLE_SUBFINDER_OUTPUT, encoding="utf-8")

        subdomains = parse_subfinder_output(output_path)

    assert subdomains == ["www.example.com", "api.example.com"]


def test_save_subdomains_json() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        output_path = temp_path / "parsed" / "subdomains.json"

        saved_path = save_subdomains_json(
            ["www.example.com", "api.example.com"],
            output_path,
        )
        saved_text = output_path.read_text(encoding="utf-8")

    assert saved_path == output_path
    assert '"www.example.com"' in saved_text
    assert '"api.example.com"' in saved_text
