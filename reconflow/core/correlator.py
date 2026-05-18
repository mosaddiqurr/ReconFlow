"""Correlation engine for turning parsed artifacts into findings."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from reconflow.core.scorer import (
    calculate_overall_risk_score,
    get_finding_rule,
    load_risk_rules,
    score_for_rule,
)
from reconflow.models.asset import Asset
from reconflow.models.crawled_url import CrawledUrl
from reconflow.models.endpoint import Endpoint
from reconflow.models.finding import Finding
from reconflow.models.live_host import LiveHost
from reconflow.models.service import Service
from reconflow.models.technology import Technology
from reconflow.models.vulnerability import Vulnerability


ADMIN_LOGIN_MARKERS = ("admin", "login", "dashboard")
BACKUP_CONFIG_MARKERS = (
    "backup",
    "config",
    ".bak",
    ".old",
    ".orig",
    ".save",
    ".sql",
    ".zip",
    ".tar",
    ".gz",
    ".env",
    "web.config",
    "config.php",
)
INTERESTING_URL_MARKERS = (
    "login",
    "admin",
    "api",
    "upload",
    "reset",
    "token",
    "callback",
    "redirect",
    "backup",
    "config",
    "dashboard",
    "wp-admin",
)
DEV_STAGE_HOST_PATTERN = re.compile(
    r"(^|[.-])(dev|development|stage|staging|test|qa|uat|beta|preprod|sandbox)([.-]|$)",
    re.IGNORECASE,
)
DATABASE_PORTS = {
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    5432: "postgresql",
    5984: "couchdb",
    6379: "redis",
    9042: "cassandra",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}
DATABASE_SERVICE_MARKERS = (
    "mysql",
    "postgres",
    "postgresql",
    "mongodb",
    "mongo",
    "redis",
    "mssql",
    "oracle",
    "elasticsearch",
    "couchdb",
    "cassandra",
    "memcached",
)


@dataclass(frozen=True)
class CorrelationResult:
    findings: list[Finding]
    overall_risk_score: int
    output_path: Path


@dataclass
class ParsedScanData:
    assets: list[Asset]
    live_hosts: list[LiveHost]
    services: list[Service]
    endpoints: list[Endpoint]
    crawled_urls: list[CrawledUrl]
    technologies: list[Technology]
    vulnerabilities: list[Vulnerability]


def correlate_scan(
    scan_folder: str | Path,
    rules_path: str | Path | None = None,
) -> CorrelationResult:
    """Correlate parsed scan artifacts and save findings.json."""
    scan_path = Path(scan_folder)
    rules = load_risk_rules(rules_path)
    data = load_parsed_scan_data(scan_path)
    findings = build_findings(data, rules)
    overall_risk_score = calculate_overall_risk_score(findings, rules)
    output_path = save_findings_json(
        findings,
        scan_path / "parsed" / "findings.json",
        overall_risk_score,
    )
    return CorrelationResult(
        findings=findings,
        overall_risk_score=overall_risk_score,
        output_path=output_path,
    )


def load_parsed_scan_data(scan_folder: str | Path) -> ParsedScanData:
    """Load parsed scan JSON artifacts if they exist."""
    parsed_dir = Path(scan_folder) / "parsed"
    return ParsedScanData(
        assets=_load_models(parsed_dir / "assets.json", Asset),
        live_hosts=_load_models(parsed_dir / "live_hosts.json", LiveHost),
        services=_load_models(parsed_dir / "services.json", Service),
        endpoints=_load_models(parsed_dir / "endpoints.json", Endpoint),
        crawled_urls=_load_models(parsed_dir / "crawled_urls.json", CrawledUrl),
        technologies=_load_models(parsed_dir / "technologies.json", Technology),
        vulnerabilities=_load_models(
            parsed_dir / "vulnerabilities.json",
            Vulnerability,
        ),
    )


def build_findings(
    data: ParsedScanData,
    rules: dict | None = None,
) -> list[Finding]:
    """Build correlated findings from parsed scan data."""
    rule_set = rules if rules is not None else load_risk_rules()
    findings: list[Finding] = []
    endpoint_candidates = _endpoint_candidates(data.endpoints, data.crawled_urls)

    findings.extend(_public_admin_login_findings(endpoint_candidates, rule_set))
    findings.extend(_wordpress_admin_findings(endpoint_candidates, data.technologies, rule_set))
    findings.extend(_development_host_findings(data, rule_set))
    findings.extend(_backup_config_findings(endpoint_candidates, rule_set))
    findings.extend(_open_database_service_findings(data.services, rule_set))
    findings.extend(_interesting_endpoint_findings(endpoint_candidates, rule_set))
    findings.extend(_nuclei_high_critical_findings(data.vulnerabilities, rule_set))
    findings.extend(_multiple_service_findings(data.services, rule_set))

    return _dedupe_findings(findings)


def save_findings_json(
    findings: list[Finding],
    output_path: str | Path,
    overall_risk_score: int,
) -> Path:
    """Save correlated findings and the overall risk score as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "overall_risk_score": overall_risk_score,
        "findings": [finding.model_dump() for finding in findings],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def correlate(parsed_items: list[dict]) -> dict:
    """Compatibility helper for callers that already have finding dictionaries."""
    rules = load_risk_rules()
    findings = [Finding.model_validate(item) for item in parsed_items]
    return {
        "overall_risk_score": calculate_overall_risk_score(findings, rules),
        "findings": [finding.model_dump() for finding in findings],
    }


def _public_admin_login_findings(
    endpoints: list[Endpoint],
    rules: dict,
) -> list[Finding]:
    findings = []
    for endpoint in endpoints:
        if _has_marker(endpoint.path, ADMIN_LOGIN_MARKERS):
            findings.append(
                _make_finding(
                    "public_admin_login_surface",
                    endpoint.host,
                    endpoint.url,
                    [
                        f"Public endpoint {endpoint.path} was discovered",
                        _status_evidence(endpoint.status_code),
                    ],
                    [endpoint.source_tool],
                    rules,
                )
            )
    return findings


def _wordpress_admin_findings(
    endpoints: list[Endpoint],
    technologies: list[Technology],
    rules: dict,
) -> list[Finding]:
    wordpress_hosts = {
        technology.host
        for technology in technologies
        if technology.name.lower() == "wordpress"
    }
    findings = []
    for endpoint in endpoints:
        if "wp-admin" not in endpoint.path.lower() and endpoint.host not in wordpress_hosts:
            continue
        if "wp-admin" not in endpoint.path.lower():
            continue
        source_tools = [endpoint.source_tool]
        if endpoint.host in wordpress_hosts:
            source_tools.append("whatweb")
        findings.append(
            _make_finding(
                "wordpress_admin_surface",
                endpoint.host,
                endpoint.url,
                [
                    f"WordPress administrative path {endpoint.path} was discovered",
                    _status_evidence(endpoint.status_code),
                ],
                source_tools,
                rules,
            )
        )
    return findings


def _development_host_findings(
    data: ParsedScanData,
    rules: dict,
) -> list[Finding]:
    host_sources: dict[str, set[str]] = {}

    def add_host(host: str, source_tool: str) -> None:
        normalized_host = _normalize_host(host)
        if normalized_host:
            host_sources.setdefault(normalized_host, set()).add(source_tool)

    for asset in data.assets:
        add_host(asset.hostname, asset.source_tool)
    for live_host in data.live_hosts:
        add_host(live_host.host, live_host.source_tool)
    for endpoint in data.endpoints:
        add_host(endpoint.host, endpoint.source_tool)
    for crawled_url in data.crawled_urls:
        add_host(crawled_url.host, crawled_url.source_tool)
    for service in data.services:
        add_host(service.host, service.source_tool)
    for vulnerability in data.vulnerabilities:
        add_host(vulnerability.host, vulnerability.source_tool)
        add_host(vulnerability.matched_url, vulnerability.source_tool)

    findings = []
    for host, source_tools in sorted(host_sources.items()):
        if DEV_STAGE_HOST_PATTERN.search(host):
            findings.append(
                _make_finding(
                    "development_or_staging_host",
                    host,
                    None,
                    [f"Host name suggests non-production exposure: {host}"],
                    sorted(source_tools),
                    rules,
                )
            )
    return findings


def _backup_config_findings(
    endpoints: list[Endpoint],
    rules: dict,
) -> list[Finding]:
    findings = []
    for endpoint in endpoints:
        if _has_marker(endpoint.url, BACKUP_CONFIG_MARKERS):
            findings.append(
                _make_finding(
                    "exposed_backup_config_file",
                    endpoint.host,
                    endpoint.url,
                    [
                        f"Potential backup/config path was discovered: {endpoint.path}",
                        _status_evidence(endpoint.status_code),
                    ],
                    [endpoint.source_tool],
                    rules,
                )
            )
    return findings


def _open_database_service_findings(
    services: list[Service],
    rules: dict,
) -> list[Finding]:
    findings = []
    for service in services:
        service_name = service.service_name.lower()
        if service.port not in DATABASE_PORTS and not any(
            marker in service_name for marker in DATABASE_SERVICE_MARKERS
        ):
            continue
        findings.append(
            _make_finding(
                "open_database_service_port",
                service.host,
                None,
                [
                    (
                        f"Open {service.protocol}/{service.port} "
                        f"service detected as {service.service_name or 'unknown'}"
                    )
                ],
                [service.source_tool],
                rules,
            )
        )
    return findings


def _interesting_endpoint_findings(
    endpoints: list[Endpoint],
    rules: dict,
) -> list[Finding]:
    findings = []
    for endpoint in endpoints:
        if not endpoint.interesting and not _has_marker(
            endpoint.url,
            INTERESTING_URL_MARKERS,
        ):
            continue
        findings.append(
            _make_finding(
                "interesting_endpoint_discovered",
                endpoint.host,
                endpoint.url,
                [f"Interesting URL pattern matched: {endpoint.path}"],
                [endpoint.source_tool],
                rules,
            )
        )
    return findings


def _nuclei_high_critical_findings(
    vulnerabilities: list[Vulnerability],
    rules: dict,
) -> list[Finding]:
    findings = []
    for vulnerability in vulnerabilities:
        severity = vulnerability.severity.lower()
        if severity not in {"high", "critical"}:
            continue
        rule = get_finding_rule("nuclei_high_or_critical_finding", rules)
        title_prefix = rule.get("title", "Nuclei high or critical finding")
        findings.append(
            _make_finding(
                "nuclei_high_or_critical_finding",
                _host_from_url_or_host(vulnerability.host or vulnerability.matched_url),
                vulnerability.matched_url,
                [
                    f"{vulnerability.template_id}: {vulnerability.name}",
                    *(f"{key}: {value}" for key, value in vulnerability.evidence.items()),
                ],
                [vulnerability.source_tool],
                rules,
                severity=severity,
                title=f"{title_prefix}: {vulnerability.name}",
            )
        )
    return findings


def _multiple_service_findings(
    services: list[Service],
    rules: dict,
) -> list[Finding]:
    rule = get_finding_rule("multiple_exposed_services_on_one_host", rules)
    min_open_services = int(rule.get("min_open_services", 3))
    services_by_host: dict[str, list[Service]] = {}
    for service in services:
        services_by_host.setdefault(service.host, []).append(service)

    findings = []
    for host, host_services in sorted(services_by_host.items()):
        if len(host_services) < min_open_services:
            continue
        service_summary = ", ".join(
            f"{service.port}/{service.service_name or service.protocol}"
            for service in sorted(host_services, key=lambda item: item.port)
        )
        findings.append(
            _make_finding(
                "multiple_exposed_services_on_one_host",
                host,
                None,
                [f"Open services on one host: {service_summary}"],
                sorted({service.source_tool for service in host_services}),
                rules,
            )
        )
    return findings


def _make_finding(
    rule_id: str,
    affected_host: str,
    affected_url: str | None,
    evidence: list[str],
    source_tools: list[str],
    rules: dict,
    severity: str | None = None,
    title: str | None = None,
) -> Finding:
    rule = get_finding_rule(rule_id, rules)
    finding_severity = (severity or rule.get("severity") or "low").lower()
    return Finding(
        title=title or rule.get("title", rule_id.replace("_", " ").title()),
        severity=finding_severity,
        risk_score=score_for_rule(rule_id, finding_severity, rules),
        affected_host=_normalize_host(affected_host) or affected_host,
        affected_url=affected_url,
        evidence=[item for item in evidence if item],
        source_tools=sorted({tool for tool in source_tools if tool}),
        recommendation=rule.get("recommendation", "Review and remediate as appropriate."),
    )


def _endpoint_candidates(
    endpoints: list[Endpoint],
    crawled_urls: list[CrawledUrl],
) -> list[Endpoint]:
    candidates = list(endpoints)
    existing_urls = {endpoint.url for endpoint in candidates}
    for crawled_url in crawled_urls:
        if crawled_url.url in existing_urls or not _has_marker(
            crawled_url.url,
            INTERESTING_URL_MARKERS,
        ):
            continue
        candidates.append(
            Endpoint(
                url=crawled_url.url,
                host=crawled_url.host,
                path=crawled_url.path,
                source_tool=crawled_url.source_tool,
                interesting=True,
            )
        )
        existing_urls.add(crawled_url.url)
    return candidates


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, str | None], Finding] = {}
    for finding in findings:
        key = (finding.title, finding.affected_host, finding.affected_url)
        if key not in unique:
            unique[key] = finding
            continue
        existing = unique[key]
        unique[key] = existing.model_copy(
            update={
                "evidence": sorted(set(existing.evidence + finding.evidence)),
                "source_tools": sorted(
                    set(existing.source_tools + finding.source_tools)
                ),
                "risk_score": max(existing.risk_score, finding.risk_score),
            }
        )
    return sorted(
        unique.values(),
        key=lambda item: (-item.risk_score, item.title, item.affected_host),
    )


def _load_models(path: Path, model_class):
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "findings" in payload:
        payload = payload["findings"]
    if not isinstance(payload, list):
        return []
    return [model_class.model_validate(item) for item in payload]


def _has_marker(value: str, markers: tuple[str, ...]) -> bool:
    normalized_value = value.lower()
    return any(marker in normalized_value for marker in markers)


def _normalize_host(value: str) -> str:
    if not value:
        return ""
    parsed_value = _host_from_url_or_host(value)
    return parsed_value.strip().lower()


def _host_from_url_or_host(value: str) -> str:
    parsed = urlparse(value)
    if parsed.netloc:
        return parsed.netloc
    return value.split("/")[0]


def _status_evidence(status_code: int | None) -> str:
    return f"HTTP status code: {status_code}" if status_code is not None else ""
