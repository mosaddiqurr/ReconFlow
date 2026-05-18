# Tool Workflow

ReconFlow chooses tools based on target type, scan mode, and parsed outputs from earlier steps. The workflow is intentionally conservative and explainable.

## Scan Modes

### Quick

```text
nmap -> httpx
```

Quick mode provides basic network and web probing.

### Standard

```text
subfinder -> dnsx -> nmap -> httpx -> whatweb -> feroxbuster -> nuclei
```

Standard mode adds passive subdomain discovery, DNS resolution, technology fingerprinting, conservative content discovery, and detection-focused Nuclei checks.

### Deep

```text
subfinder -> dnsx -> nmap -> httpx -> whatweb -> feroxbuster -> katana -> nuclei -> gowitness
```

Deep mode adds crawling and screenshots for authorized review.

## Decision Rules

| Rule | Result |
| --- | --- |
| Target is a domain | Subfinder can run |
| Subdomains exist | dnsx can run |
| Resolved hosts exist | httpx probes resolved hosts |
| DNS resolution is not planned | httpx can probe the original target |
| Live web hosts exist | WhatWeb, Feroxbuster, Katana, Nuclei, and Gowitness can run |
| Required input is missing | Step is skipped with a reason |
| Dry-run is enabled | No external tools execute |

## Outputs by Tool

| Tool | Raw output | Parsed output |
| --- | --- | --- |
| Subfinder | `raw/subfinder.txt` | `parsed/subdomains.json` |
| dnsx | `raw/dnsx.jsonl` | `parsed/assets.json` |
| Nmap | `raw/nmap.xml` | `parsed/services.json` |
| httpx | `raw/httpx.jsonl` | `parsed/live_hosts.json` |
| WhatWeb | `raw/whatweb.json` | `parsed/technologies.json` |
| Feroxbuster | `raw/feroxbuster.json` | `parsed/endpoints.json` |
| Katana | `raw/katana.jsonl` | `parsed/crawled_urls.json` |
| Nuclei | `raw/nuclei.jsonl` | `parsed/vulnerabilities.json` |
| Gowitness | `screenshots/` | `parsed/screenshots.json` |

## Correlation and Scoring

After tool parsing, ReconFlow builds `parsed/findings.json`. The correlation engine currently identifies:

- Public admin or login surface
- WordPress admin surface
- Development or staging host
- Exposed backup or config file
- Open database or service port
- Interesting endpoint
- High or critical Nuclei observation
- Multiple exposed services on one host

Risk scores are loaded from:

```text
reconflow/data/rules/risk_rules.yaml
```

## Reports

When parsed data exists, ReconFlow can generate:

```text
reports/report.md
reports/report.html
reports/report.json
```

Reports use parsed artifacts and prioritize `findings.json`.

## Missing Tools

If an external command is missing, ReconFlow shows:

- Tool name
- Why the tool was needed
- Install note
- Whether the step was skipped

Downstream steps may also be skipped if the missing tool means required parsed input was never produced.
