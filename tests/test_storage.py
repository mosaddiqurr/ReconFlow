from pathlib import Path
from tempfile import TemporaryDirectory

from reconflow.core.storage import (
    create_scan_folder,
    read_scan_history,
    read_scan_metadata,
    write_scan_metadata,
)


def test_scan_folder_creation() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        metadata = create_scan_folder(
            target="example.com",
            target_type="domain",
            mode="standard",
            base_dir=temp_path / "scans",
            tools_planned=["nmap", "subfinder"],
        )

        scan_dir = temp_path / "scans" / "scan_001_example_com"

        assert metadata["scan_id"] == "scan_001_example_com"
        assert scan_dir.is_dir()
        assert (scan_dir / "raw").is_dir()
        assert (scan_dir / "parsed").is_dir()
        assert (scan_dir / "screenshots").is_dir()
        assert (scan_dir / "reports").is_dir()
        assert (scan_dir / "metadata.json").is_file()


def test_metadata_writing() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        metadata = create_scan_folder(
            target="example.com",
            target_type="domain",
            mode="quick",
            base_dir=temp_path / "scans",
            tools_planned=["nmap"],
        )

        scan_dir = temp_path / "scans" / "scan_001_example_com"
        written_metadata = read_scan_metadata(scan_dir / "metadata.json")

        assert written_metadata["scan_id"] == metadata["scan_id"]
        assert written_metadata["target"] == "example.com"
        assert written_metadata["target_type"] == "domain"
        assert written_metadata["mode"] == "quick"
        assert written_metadata["status"] == "initialized"
        assert written_metadata["output_dir"] == str(scan_dir)
        assert written_metadata["tools_planned"] == ["nmap"]
        assert written_metadata["tools_completed"] == []
        assert written_metadata["start_time"]
        assert written_metadata["end_time"]


def test_metadata_reading() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        scan_dir = temp_path / "scans" / "scan_001_example_com"
        scan_dir.mkdir(parents=True)
        metadata = {
            "scan_id": "scan_001_example_com",
            "target": "example.com",
            "target_type": "domain",
            "mode": "standard",
            "start_time": "2026-05-18T00:00:00+00:00",
            "end_time": "2026-05-18T00:00:01+00:00",
            "status": "initialized",
            "output_dir": str(scan_dir),
            "tools_planned": ["nmap"],
            "tools_completed": [],
        }
        write_scan_metadata(scan_dir, metadata)

        history = read_scan_history(temp_path / "scans")

        assert history == [metadata]
