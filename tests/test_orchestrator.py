from reconflow.core.orchestrator import Orchestrator, WorkflowState


def test_domain_runs_subfinder() -> None:
    state = WorkflowState(
        target="example.com",
        target_type="domain",
        mode="standard",
        planned_tools=["subfinder"],
    )

    decision = Orchestrator().decide("subfinder", state)

    assert decision.should_run is True
    assert decision.input_description == "example.com"
    assert "subdomain" in decision.output_description


def test_non_domain_skips_subfinder() -> None:
    state = WorkflowState(
        target="93.184.216.34",
        target_type="ip",
        mode="standard",
        planned_tools=["subfinder"],
    )

    decision = Orchestrator().decide("subfinder", state)

    assert decision.should_run is False
    assert decision.skip_reason == "Target type is ip, not domain."


def test_dnsx_runs_only_with_subdomains() -> None:
    orchestrator = Orchestrator()
    empty_state = WorkflowState(
        target="example.com",
        target_type="domain",
        mode="standard",
        planned_tools=["dnsx"],
    )
    ready_state = WorkflowState(
        target="example.com",
        target_type="domain",
        mode="standard",
        planned_tools=["dnsx"],
        subdomains=["www.example.com"],
    )

    assert orchestrator.decide("dnsx", empty_state).should_run is False
    assert orchestrator.decide("dnsx", ready_state).should_run is True


def test_httpx_uses_resolved_hosts_when_available() -> None:
    state = WorkflowState(
        target="example.com",
        target_type="domain",
        mode="standard",
        planned_tools=["dnsx", "httpx"],
        resolved_hosts=["www.example.com"],
    )

    decision = Orchestrator().decide("httpx", state)

    assert decision.should_run is True
    assert decision.input_description == "parsed/assets.json"


def test_httpx_skips_when_dnsx_planned_without_resolved_hosts() -> None:
    state = WorkflowState(
        target="example.com",
        target_type="domain",
        mode="standard",
        planned_tools=["dnsx", "httpx"],
    )

    decision = Orchestrator().decide("httpx", state)

    assert decision.should_run is False
    assert decision.skip_reason == "No resolved hosts are available."


def test_live_web_tools_run_only_with_live_hosts() -> None:
    orchestrator = Orchestrator()
    empty_state = WorkflowState(
        target="example.com",
        target_type="domain",
        mode="standard",
        planned_tools=["whatweb"],
    )
    ready_state = WorkflowState(
        target="example.com",
        target_type="domain",
        mode="standard",
        planned_tools=["whatweb"],
        live_hosts=["https://www.example.com"],
    )

    assert orchestrator.decide("whatweb", empty_state).should_run is False
    assert orchestrator.decide("whatweb", ready_state).should_run is True


def test_nmap_uses_resolved_assets_in_deep_mode() -> None:
    state = WorkflowState(
        target="example.com",
        target_type="domain",
        mode="deep",
        planned_tools=["nmap"],
        resolved_hosts=["www.example.com"],
    )

    decision = Orchestrator().decide("nmap", state)

    assert decision.should_run is True
    assert decision.input_description == "resolved assets from parsed/assets.json"
