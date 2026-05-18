# ReconFlow Architecture

ReconFlow is organized as an explainable reconnaissance orchestration system. Its job is to coordinate safe tool execution, parse outputs into structured models, correlate observations, and generate reports.

## Design Goals

- Keep workflow decisions understandable.
- Keep parsing and execution separate.
- Store raw artifacts and parsed artifacts side by side.
- Prefer JSON outputs for repeatable testing and reporting.
- Support dry-run and explain modes for learning.
- Avoid aggressive defaults.

## High-Level Flow

```text
target
  -> validation
  -> workflow planning
  -> per-step orchestration decision
  -> optional external tool execution
  -> raw artifact
  -> parser
  -> parsed JSON model
  -> correlation and scoring
  -> reports
  -> optional scan comparison
```

## Package Layout

| Path | Responsibility |
| --- | --- |
| `reconflow/cli.py` | Typer commands, Rich output, scan/report/compare entry points |
| `reconflow/core/workflow.py` | Scan mode definitions and ordered workflow steps |
| `reconflow/core/orchestrator.py` | Per-step run or skip decisions based on current state |
| `reconflow/core/runner.py` | Safe subprocess wrapper returning structured results |
| `reconflow/core/storage.py` | Scan folder and metadata helpers |
| `reconflow/core/correlator.py` | Converts parsed data into findings |
| `reconflow/core/scorer.py` | Risk scoring from YAML rules |
| `reconflow/core/comparator.py` | Parsed artifact diff between scans |
| `reconflow/tools/` | Tool-specific command builders, parsers, and runners |
| `reconflow/models/` | Pydantic models for normalized data |
| `reconflow/reports/` | Markdown, HTML, and JSON report generation |
| `reconflow/data/rules/` | Correlation and risk scoring configuration |

## Workflow State

Workflow state is updated as each parser succeeds:

- Subfinder updates `subdomains`
- dnsx updates `resolved_hosts`
- httpx updates `live_hosts`

Downstream decisions are recomputed immediately before each step. This keeps the CLI from using stale skip decisions.

## Scan Folder Structure

Each scan is saved under `scans/<scan_id>/`:

```text
scans/scan_001_example_com/
  metadata.json
  raw/
  parsed/
  screenshots/
  reports/
```

Raw files are preserved for traceability. Parsed files are used for correlation, reports, and comparison.

## Safety Model

ReconFlow requires `--i-authorize` for scans. It also supports `--dry-run`, which shows planned commands without calling external tool runners.

Missing tools, failed commands, and timeouts are handled as structured scan events. They are shown in Rich tables and recorded in metadata.

## Reporting Pipeline

Reports are generated from parsed JSON artifacts. `findings.json` is the primary prioritized source for report findings. Markdown and HTML reports use Jinja2 templates; JSON reports are emitted as structured data.

## Comparison Pipeline

Scan comparison reads parsed JSON from two scan folders and computes deltas for subdomains, live hosts, open ports, technologies, endpoints, vulnerability observations, and correlated findings. It does not rerun tools.
