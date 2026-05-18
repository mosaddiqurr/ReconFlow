"""High-level workflow orchestration decisions."""

from dataclasses import dataclass, field

from reconflow.core.workflow import get_workflow_steps


@dataclass
class WorkflowState:
    target: str
    target_type: str
    mode: str
    planned_tools: list[str]
    subdomains: list[str] = field(default_factory=list)
    resolved_hosts: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)

    @property
    def live_web_hosts(self) -> list[str]:
        return self.live_hosts

    @live_web_hosts.setter
    def live_web_hosts(self, value: list[str]) -> None:
        self.live_hosts = value


@dataclass(frozen=True)
class WorkflowDecision:
    tool_name: str
    should_run: bool
    reason: str
    input_description: str
    output_description: str
    skip_reason: str = ""


class Orchestrator:
    """Coordinates workflow decisions from target type and prior results."""

    def plan(
        self,
        mode: str,
        enabled_tools: list[str] | tuple[str, ...] | None = None,
    ) -> list[str]:
        return [step.name for step in get_workflow_steps(mode, enabled_tools)]

    def decide(self, tool_name: str, state: WorkflowState) -> WorkflowDecision:
        if tool_name not in state.planned_tools:
            return WorkflowDecision(
                tool_name=tool_name,
                should_run=False,
                reason="Tool is not part of the selected scan mode.",
                input_description="-",
                output_description="-",
                skip_reason="Not planned for this scan mode.",
            )

        handlers = {
            "subfinder": self._subfinder,
            "dnsx": self._dnsx,
            "httpx": self._httpx,
            "nmap": self._nmap,
            "whatweb": self._live_web_tool,
            "feroxbuster": self._live_web_tool,
            "katana": self._live_web_tool,
            "nuclei": self._live_web_tool,
            "gowitness": self._live_web_tool,
        }
        handler = handlers.get(tool_name)
        if handler is None:
            return WorkflowDecision(
                tool_name=tool_name,
                should_run=False,
                reason="No orchestration rule exists for this tool.",
                input_description="-",
                output_description="-",
                skip_reason="Unsupported workflow step.",
            )

        return handler(tool_name, state)

    def _subfinder(self, tool_name: str, state: WorkflowState) -> WorkflowDecision:
        if state.target_type != "domain":
            return WorkflowDecision(
                tool_name=tool_name,
                should_run=False,
                reason="Subfinder only accepts domain targets.",
                input_description=state.target,
                output_description="parsed/subdomains.json",
                skip_reason=f"Target type is {state.target_type}, not domain.",
            )

        return WorkflowDecision(
            tool_name=tool_name,
            should_run=True,
            reason="Domain targets can be expanded with passive subdomain discovery.",
            input_description=state.target,
            output_description="raw/subfinder.txt and parsed/subdomains.json",
        )

    def _dnsx(self, tool_name: str, state: WorkflowState) -> WorkflowDecision:
        if not state.subdomains:
            return WorkflowDecision(
                tool_name=tool_name,
                should_run=False,
                reason="dnsx requires parsed subdomains.",
                input_description="parsed/subdomains.json",
                output_description="raw/dnsx.jsonl and parsed/assets.json",
                skip_reason="No subdomains are available.",
            )

        return WorkflowDecision(
            tool_name=tool_name,
            should_run=True,
            reason="Parsed subdomains are available for DNS resolution.",
            input_description="parsed/subdomains.json",
            output_description="raw/dnsx.jsonl and parsed/assets.json",
        )

    def _httpx(self, tool_name: str, state: WorkflowState) -> WorkflowDecision:
        if state.resolved_hosts:
            return WorkflowDecision(
                tool_name=tool_name,
                should_run=True,
                reason="Resolved hosts are available for HTTP probing.",
                input_description="parsed/assets.json",
                output_description="raw/httpx.jsonl and parsed/live_hosts.json",
            )

        if "dnsx" not in state.planned_tools:
            return WorkflowDecision(
                tool_name=tool_name,
                should_run=True,
                reason="No DNS-resolution step is planned, so the original target is probed.",
                input_description=state.target,
                output_description="raw/httpx.jsonl and parsed/live_hosts.json",
            )

        return WorkflowDecision(
            tool_name=tool_name,
            should_run=False,
            reason="httpx requires resolved hosts when DNS resolution is planned.",
            input_description="parsed/assets.json",
            output_description="raw/httpx.jsonl and parsed/live_hosts.json",
            skip_reason="No resolved hosts are available.",
        )

    def _nmap(self, tool_name: str, state: WorkflowState) -> WorkflowDecision:
        if state.mode == "deep" and state.resolved_hosts:
            input_description = "resolved assets from parsed/assets.json"
            reason = "Deep mode runs Nmap against resolved assets when available."
        else:
            input_description = state.target
            reason = "Nmap always runs for baseline network and service discovery."

        return WorkflowDecision(
            tool_name=tool_name,
            should_run=True,
            reason=reason,
            input_description=input_description,
            output_description="raw/nmap.xml and parsed/services.json",
        )

    def _live_web_tool(
        self,
        tool_name: str,
        state: WorkflowState,
    ) -> WorkflowDecision:
        outputs = {
            "whatweb": "raw/whatweb.json and parsed/technologies.json",
            "feroxbuster": "raw/feroxbuster.json and parsed/endpoints.json",
            "katana": "raw/katana.jsonl and parsed/crawled_urls.json",
            "nuclei": "raw/nuclei.jsonl and parsed/vulnerabilities.json",
            "gowitness": "screenshots/ and parsed/screenshots.json",
        }
        if not state.live_hosts:
            return WorkflowDecision(
                tool_name=tool_name,
                should_run=False,
                reason=f"{tool_name} requires live web hosts.",
                input_description="parsed/live_hosts.json",
                output_description=outputs[tool_name],
                skip_reason="No live web hosts are available.",
            )

        return WorkflowDecision(
            tool_name=tool_name,
            should_run=True,
            reason=f"Live web hosts are available for {tool_name}.",
            input_description="parsed/live_hosts.json",
            output_description=outputs[tool_name],
        )
