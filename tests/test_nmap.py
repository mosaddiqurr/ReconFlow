from pathlib import Path
from tempfile import TemporaryDirectory

from reconflow.tools.nmap import build_nmap_command, parse_nmap_xml, save_services_json


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
