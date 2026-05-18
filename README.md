# ReconFlow

ReconFlow is an explainable reconnaissance orchestration CLI for students and junior analysts practicing authorized security testing.

## Problem Statement

Reconnaissance workflows often spread across many command-line tools, output formats, notes, and ad hoc scripts. For learners, that makes it hard to understand what ran, why it ran, what was skipped, and how raw observations become useful findings.

ReconFlow focuses on the orchestration layer: safe workflow decisions, structured parsed outputs, correlation, scoring, reports, and scan comparison. It is designed as a portfolio project and learning aid where human review and validation remain central.

## What ReconFlow Solves

ReconFlow turns a target and scan mode into an explainable recon workflow. It records tool decisions, stores raw and parsed artifacts, correlates observations into prioritized findings, and generates reports from parsed JSON data.

The tool is intentionally conservative. It requires explicit authorization confirmation, supports dry-run mode, skips steps when required input is missing, and uses safe defaults for detection-focused tooling.

## Key Features

- Typer-based CLI with Rich output.
- Explainable workflow decisions with run and skip reasons.
- Dry-run mode that does not execute external tools.
- Structured scan folders with raw, parsed, screenshots, and reports output.
- Tool availability checks and clear missing-tool install guidance.
- Parsed models for assets, services, live hosts, technologies, endpoints, vulnerabilities, screenshots, and findings.
- Correlation engine for common attack-surface observations.
- Risk scoring from YAML rules.
- Markdown, HTML, and JSON report generation.
- Scan-to-scan comparison for new and resolved observations.
- Tests built around sample and mocked outputs rather than live tools.

## Tool Integrations

ReconFlow currently integrates with:

| Tool | Purpose |
| --- | --- |
| Nmap | Network and service discovery |
| Subfinder | Passive subdomain discovery |
| dnsx | DNS probing and resolution |
| httpx | HTTP probing and web metadata collection |
| WhatWeb | Web technology fingerprinting |
| Feroxbuster | Content and directory discovery |
| Katana | Web crawling and URL discovery |
| Nuclei | Template-based detection and reporting |
| Gowitness | Website screenshot capture |

External tools are not bundled. Install only the tools you intend to use and only run them against systems you are authorized to test.

## Architecture Overview

ReconFlow separates workflow decisions from execution and reporting:

- `reconflow/core/workflow.py` defines scan modes and ordered steps.
- `reconflow/core/orchestrator.py` decides whether each step should run based on target type and previous parsed results.
- `reconflow/tools/` contains command builders, runners, and parsers for each external integration.
- `reconflow/models/` contains Pydantic models for normalized parsed data.
- `reconflow/core/correlator.py` converts parsed observations into prioritized findings.
- `reconflow/core/scorer.py` calculates finding and overall risk scores from YAML rules.
- `reconflow/reports/` renders Markdown, HTML, and JSON reports.
- `reconflow/core/comparator.py` compares parsed artifacts between two scans.

More detail is available in [docs/architecture.md](docs/architecture.md).

## Installation

Requirements:

- Python 3.10+
- External tools installed separately as needed

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS or Linux:

```bash
source .venv/bin/activate
```

Install dependencies and the local CLI:

```bash
pip install -r requirements.txt
pip install -e .
```

Check available commands:

```bash
reconflow --help
```

## Usage Examples

Dry-run a quick scan without executing tools:

```bash
reconflow scan example.com --mode quick --i-authorize --dry-run
```

Explain a standard workflow:

```bash
reconflow scan example.com --mode standard --explain --i-authorize --dry-run
```

Run a standard scan against an authorized target:

```bash
reconflow scan example.com --mode standard --i-authorize
```

Generate reports for an existing scan:

```bash
reconflow report scan_001_example_com --format all
```

Compare two scans:

```bash
reconflow compare scan_001_example_com scan_002_example_com
```

Check installed external tools:

```bash
reconflow tools check
```

## Sample Output

Example dry-run output is intentionally readable and decision-focused:

```text
Target Summary
Target                  example.com
Target Type             domain
Scan Mode               standard
Authorization           Confirmed

Workflow Summary
1  subfinder     Passive subdomain discovery
2  dnsx          DNS probing and resolution
3  nmap          Network and service discovery
4  httpx         HTTP probing and web metadata collection

Step Progress
subfinder: Ready
Domain targets can be expanded with passive subdomain discovery.

Skipped dnsx: No subdomains are available.

ReconFlow Scan Summary
Correlated Findings     0
Overall Risk Score      0
Reports Generated       markdown, html, json
```

Actual output includes Rich panels and tables, plus saved files under the scan folder.

## Reports

Each scan can generate:

- `reports/report.md`
- `reports/report.html`
- `reports/report.json`

Report sections include executive summary, target scope, tools used, workflow, assets, live hosts, services, technologies, interesting endpoints, parsed vulnerability observations, prioritized findings, overall risk score, recommendations, and evidence appendix.

Report screenshots placeholder:

```text
docs/assets/report-screenshot-placeholder.png
```

Add screenshots here after generating a local sample report. Do not commit sensitive client or production scan screenshots.

See [docs/sample-report.md](docs/sample-report.md) for a sanitized example.

## Sample Fixture Data

Small synthetic examples are available under [docs/sample-data](docs/sample-data). They are documentation fixtures only and are not real scan results.

## Safety and Authorization Notice

ReconFlow is for authorized testing only. Use it only on systems you own or where you have explicit written permission to test. Do not use it for unauthorized reconnaissance, exploitation, disruption, or data access.

The project is built to support explainable detection and reporting workflows. It does not perform exploitation and should not be used to bypass access controls.

## Roadmap

- Add richer report styling and optional static assets.
- Add configuration examples for lab environments.
- Improve comparison summaries with severity-aware deltas.
- Add import/export helpers for teaching datasets.
- Add more parser fixtures for edge cases.
- Add CI workflow for tests and lint checks.
- Improve documentation screenshots after stable report layouts.

## Disclaimer

This project is provided for educational, portfolio, and authorized security testing use only. ReconFlow should be paired with manual validation, trained security review, and responsible disclosure processes. Users are responsible for ensuring they have permission before scanning any target.
