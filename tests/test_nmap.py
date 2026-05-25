from pathlib import Path
from tempfile import TemporaryDirectory

from reconflow.config import ReconFlowConfig
from reconflow.tools.nmap import (
    build_nmap_command,
    parse_nmap_xml,
    save_services_json,
    select_nmap_targets,
)


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed" />
        <service name="ssh" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.24" />
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" product="nginx" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_build_nmap_command() -> None:
    command = build_nmap_command("example.com", "scans/scan_001/raw/nmap.xml")

    assert command == [
        "nmap",
        "-sV",
        "-oX",
        "scans/scan_001/raw/nmap.xml",
        "example.com",
    ]


def test_select_nmap_targets_deduplicates_duplicate_hostnames() -> None:
    targets = select_nmap_targets(
        "example.com",
        resolved_hosts=["www.example.com", "www.example.com", "api.example.com"],
    )

    assert targets == ["www.example.com", "api.example.com"]


def test_select_nmap_targets_ignores_cname_values() -> None:
    targets = select_nmap_targets(
        "example.com",
        assets=[
            {
                "hostname": "www.example.com",
                "ip": "edge.example.net",
                "record_type": "CNAME",
                "is_resolved": True,
            }
        ],
    )

    assert targets == ["example.com"]


def test_select_nmap_targets_prefers_unique_a_and_aaaa_ips() -> None:
    targets = select_nmap_targets(
        "example.com",
        assets=[
            {
                "hostname": "www.example.com",
                "ip": "93.184.216.34",
                "record_type": "A",
                "is_resolved": True,
            },
            {
                "hostname": "www.example.com",
                "ip": "93.184.216.34",
                "record_type": "A",
                "is_resolved": True,
            },
            {
                "hostname": "www.example.com",
                "ip": "2606:2800:220:1:248:1893:25c8:1946",
                "record_type": "AAAA",
                "is_resolved": True,
            },
            {
                "hostname": "www.example.com",
                "ip": "edge.example.net",
                "record_type": "CNAME",
                "is_resolved": True,
            },
        ],
    )

    assert targets == [
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
    ]


def test_nmap_timeout_default_and_configurable() -> None:
    assert ReconFlowConfig().tool_timeouts["nmap"] == 300
    assert ReconFlowConfig(tool_timeouts={"nmap": 120}).tool_timeouts["nmap"] == 120


def test_parse_nmap_xml_fixture() -> None:
    with TemporaryDirectory() as tmp_dir:
        xml_path = Path(tmp_dir) / "nmap.xml"
        xml_path.write_text(SAMPLE_NMAP_XML, encoding="utf-8")

        services = parse_nmap_xml(xml_path)

    assert len(services) == 2
    assert services[0].host == "93.184.216.34"
    assert services[0].port == 80
    assert services[0].protocol == "tcp"
    assert services[0].service_name == "http"
    assert services[0].product == "nginx"
    assert services[0].version == "1.24"
    assert services[0].state == "open"
    assert services[0].source_tool == "nmap"
    assert services[1].port == 443


def test_save_services_json() -> None:
    with TemporaryDirectory() as tmp_dir:
        temp_path = Path(tmp_dir)
        xml_path = temp_path / "nmap.xml"
        output_path = temp_path / "parsed" / "services.json"
        xml_path.write_text(SAMPLE_NMAP_XML, encoding="utf-8")

        services = parse_nmap_xml(xml_path)
        saved_path = save_services_json(services, output_path)
        saved_text = output_path.read_text(encoding="utf-8")

    assert saved_path == output_path
    assert '"service_name": "http"' in saved_text
    assert '"source_tool": "nmap"' in saved_text
