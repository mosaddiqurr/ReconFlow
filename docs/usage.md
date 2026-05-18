# ReconFlow Usage

ReconFlow is a command-line learning tool for authorized reconnaissance workflows.

## Install

```bash
python -m venv .venv
pip install -r requirements.txt
pip install -e .
```

Activate the virtual environment before running commands.

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS or Linux:

```bash
source .venv/bin/activate
```

## Check Help

```bash
reconflow --help
reconflow scan --help
```

## Authorization Requirement

Every scan requires explicit authorization confirmation:

```bash
reconflow scan example.com --i-authorize
```

Use ReconFlow only on systems you own or where you have explicit written permission to test.

## Dry Run

Dry-run mode prints workflow decisions and planned commands without executing external tools.

```bash
reconflow scan example.com --mode standard --i-authorize --dry-run
```

## Explain Mode

Explain mode shows why each workflow step is running or skipped.

```bash
reconflow scan example.com --mode standard --explain --i-authorize --dry-run
```

## Scan Modes

| Mode | Workflow |
| --- | --- |
| `quick` | Nmap, httpx |
| `standard` | Subfinder, dnsx, Nmap, httpx, WhatWeb, Feroxbuster, Nuclei |
| `deep` | Standard plus Katana and Gowitness |

Workflow decisions still depend on target type and previous parsed results. For example, dnsx is skipped if Subfinder produced no subdomains.

## Custom Wordlist

Feroxbuster uses a small default wordlist:

```text
reconflow/data/wordlists/common.txt
```

Use a custom wordlist for authorized testing:

```bash
reconflow scan example.com --mode standard --wordlist path/to/wordlist.txt --i-authorize
```

Do not commit large wordlists to the repository.

## Tool Check

```bash
reconflow tools check
```

This command checks whether supported external tools are available and shows install notes.

## Reports

Generate all report formats for a scan:

```bash
reconflow report scan_001_example_com --format all
```

Generate one format:

```bash
reconflow report scan_001_example_com --format markdown
reconflow report scan_001_example_com --format html
reconflow report scan_001_example_com --format json
```

Reports are saved under:

```text
scans/<scan_id>/reports/
```

## Compare Scans

```bash
reconflow compare scan_001_example_com scan_002_example_com
```

Comparison output is saved under:

```text
scans/comparisons/
```

## Common Error Cases

| Case | Behavior |
| --- | --- |
| Missing `--i-authorize` | Scan stops with an authorization warning |
| Invalid target | Scan stops with an invalid target message |
| Missing scan ID | Report or compare command shows a missing scan ID message |
| Missing parsed data | Report command explains that no parsed JSON artifacts exist |
| Missing external tool | Step is skipped with tool name, purpose, and install note |
| Timeout or failed command | Issue is shown and recorded in scan metadata |

## Manual Test Commands

```bash
reconflow scan example.com --mode quick --i-authorize --dry-run
reconflow scan example.com --mode standard --explain --i-authorize --dry-run
reconflow tools check
reconflow history
python -m pytest
```
