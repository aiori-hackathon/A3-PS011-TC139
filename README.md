# AIORI 3 — Authorized Attack-Surface Discovery & Monitoring

It is an AI-assisted cybersecurity system designed to discover and monitor an organization's authorized external attack surface. It identifies changes in DNS records, TLS certificates, and exposed network services, helping security teams detect potential risks through evidence-based alerts.

## Key Features

- **AI-Assisted Scope Recommendation:** Suggests assets for monitoring, with human approval required before scanning.
- **Secure Scope Enforcement:** Uses Ed25519 cryptographic signing and strict egress validation.
- **DNS, TLS & Port Monitoring:** Collects DNS records, checks certificate validity, and inspects selected exposed services.
- **Change Detection:** Compares current observations against a stored baseline.
- **False-Positive Analysis:** Helps reduce noisy alerts using resolver agreement and historical observations.
- **Interactive Attack-Surface Graph:** Visualizes relationships between domains, subdomains, IP addresses, ports, and certificates.
- **Auditability:** Maintains historical observations and supports integrity-protected audit records.

## Architecture

AIORI 3 follows a layered architecture:

1. **Human & Management Layer** — Scope recommendation, approval, and operator dashboard.
2. **Active Execution Layer** — Scheduled scan workers with strict network access controls.
3. **Data Processing & Storage Layer** — Data validation, change detection, risk analysis, audit storage, and alerting.

## Security

All active checks are restricted to explicitly authorized assets. The system is designed to avoid intrusive exploitation and to treat newly discovered assets as candidates until their scope is verified.

## Presentation

🎥 **YouTube Demo:** [WATCH](https://youtu.be/zWLLCSaBG18)
## Project Status

Developed as a cybersecurity project addressing Challenge PS-011: Authorized Attack-Surface Discovery and Monitoring.

**Note:** Detection accuracy and security controls should be validated through controlled tests before production use.
