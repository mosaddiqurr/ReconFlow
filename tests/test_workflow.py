import pytest

from reconflow.config import load_config
from reconflow.core.workflow import get_workflow_steps


def test_valid_mode() -> None:
    steps = get_workflow_steps("quick")

    assert [step.name for step in steps] == ["nmap", "httpx"]


def test_invalid_mode() -> None:
    with pytest.raises(ValueError, match="Invalid scan mode"):
        get_workflow_steps("invalid")


def test_default_mode() -> None:
    config = load_config()

    assert config.default_mode == "standard"


def test_workflow_step_selection() -> None:
    standard_steps = get_workflow_steps("standard")
    deep_steps = get_workflow_steps("deep")

    assert [step.name for step in standard_steps] == [
        "subfinder",
        "dnsx",
        "nmap",
        "httpx",
        "whatweb",
        "feroxbuster",
        "nuclei",
    ]
    assert [step.name for step in deep_steps] == [
        "subfinder",
        "dnsx",
        "nmap",
        "httpx",
        "whatweb",
        "feroxbuster",
        "katana",
        "nuclei",
        "gowitness",
    ]
