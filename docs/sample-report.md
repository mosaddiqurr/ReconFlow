# Sample ReconFlow Report

This is a sanitized example showing the shape of a generated report. It is not a real scan result and does not claim that any public system has these properties.

## 1. Executive Summary

ReconFlow analyzed `training.example` in `standard` mode using synthetic parsed artifacts. The overall attack surface risk score is `0/100`.

- Prioritized findings: 0
- High-priority findings: 0
- Discovered assets: 1
- Live hosts: 1
- Open services: 1
- Interesting endpoints: 0

## 2. Target Scope

| Field | Value |
| --- | --- |
| Target | training.example |
| Target type | domain |
| Scan mode | standard |
| Authorization status | Authorized fixture data |

## 3. Tools Used

- dnsx
- httpx
- nmap

## 4. Recon Workflow

1. subfinder
2. dnsx
3. nmap
4. httpx
5. whatweb
6. feroxbuster
7. nuclei

## 5. Discovered Assets

| Hostname | IP | Record type | Resolved |
| --- | --- | --- | --- |
| app.training.example | 192.0.2.10 | A | true |

## 6. Live Hosts

| URL | Host | Status | Title |
| --- | --- | --- | --- |
| https://app.training.example | app.training.example | 200 | Training Fixture |

## 7. Open Ports and Services

| Host | Port | Protocol | Service | Product |
| --- | --- | --- | --- | --- |
| 192.0.2.10 | 443 | tcp | https | nginx |

## 8. Technologies

| Host | URL | Technology | Version | Category |
| --- | --- | --- | --- | --- |
| app.training.example | https://app.training.example | nginx | 1.24 | web server |

## 9. Interesting Endpoints

No interesting endpoints are shown in this sample.

## 10. Vulnerability Findings

No vulnerability findings are included in this sample.

## 11. Prioritized Findings

No prioritized findings are included in this sample.

## 12. Overall Risk Score

`0/100`

## 13. Recommended Next Steps

- Review parsed reconnaissance data.
- Confirm all testing remains within authorized scope.
- Validate any future findings manually before treating them as security issues.

## 14. Evidence Appendix

No evidence appendix entries are included in this sample.
