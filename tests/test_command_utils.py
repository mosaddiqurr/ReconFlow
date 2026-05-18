from reconflow.utils import command_utils


def test_check_command_exists_returns_detected_path(monkeypatch) -> None:
    def fake_which(command_name: str) -> str | None:
        return "C:\\Tools\\nmap.exe" if command_name == "nmap" else None

    monkeypatch.setattr(command_utils.shutil, "which", fake_which)

    assert command_utils.check_command_exists("nmap") == "C:\\Tools\\nmap.exe"
    assert command_utils.check_command_exists("missing-tool") is None


def test_check_required_tools_uses_configured_commands(monkeypatch) -> None:
    detected_commands = {"nmap": "C:\\Tools\\nmap.exe", "httpx": "C:\\Tools\\httpx.exe"}

    def fake_which(command_name: str) -> str | None:
        return detected_commands.get(command_name)

    monkeypatch.setattr(command_utils.shutil, "which", fake_which)

    results = command_utils.check_required_tools()
    result_by_name = {result.tool.name: result for result in results}

    assert set(result_by_name) == {
        "nmap",
        "subfinder",
        "dnsx",
        "httpx",
        "whatweb",
        "feroxbuster",
        "katana",
        "nuclei",
        "gowitness",
    }
    assert result_by_name["nmap"].is_installed is True
    assert result_by_name["nmap"].detected_path == "C:\\Tools\\nmap.exe"
    assert result_by_name["httpx"].is_installed is True
    assert result_by_name["subfinder"].is_installed is False
    assert result_by_name["subfinder"].detected_path is None


def test_required_tool_metadata_has_install_notes() -> None:
    for tool in command_utils.REQUIRED_TOOLS:
        assert tool.name
        assert tool.purpose
        assert tool.command
        assert tool.install_note
