# AIORI 3 — Authorized Attack-Surface Discovery & Monitoring

AIORI 3 is an AI-assisted cybersecurity system designed to discover and monitor an organization's **authorized external attack surface**. It helps identify changes in DNS records, TLS certificates, and exposed network services, enabling security teams to detect potential risks through evidence-based alerts.

## Key Features

- **AI-Assisted Scope Recommendation:** Suggests assets for monitoring, with human approval required before scanning.
- **Secure Scope Enforcement:** Uses Ed25519 cryptographic signing and strict scope validation.
- **DNS, TLS & Port Monitoring:** Collects DNS records, checks certificate validity, and monitors selected exposed network services.
- **Change Detection:** Compares current observations against a stored baseline to identify state changes.
- **False-Positive Analysis:** Helps reduce noisy alerts using resolver agreement and historical observations.
- **Interactive Attack-Surface Graph:** Visualizes relationships between domains, subdomains, IP addresses, ports, and certificates.
- **Differential Analysis:** Detects newly opened or closed services by comparing current and baseline scan results.
- **Auditability:** Maintains historical observations and supports integrity-protected audit records.

## Project Architecture

AIORI 3 follows a layered architecture:

### 1. Human & Management Layer
Handles scope recommendation, human approval, and operator interaction.

### 2. Active Execution Layer
Performs authorized monitoring and network checks with strict scope controls.

### 3. Data Processing & Storage Layer
Handles:

- Data validation
- Network observation collection
- Change detection
- Differential analysis
- Audit logging
- Alert generation

## Project Structure

```text
AIORI-3/
│
├── collectors/
│   └── network_collector.py
│
├── core/
│   └── scope_validator.py
│
├── diff_engine/
│   └── analyzer.py
│
├── storage/
│   └── database.py
│
├── UI/
│   └── app.py
│
├── test_runner.py
├── test_scope.yaml
├── test_scope.sig
└── README.md
```

## Security

All active checks are restricted to **explicitly authorized assets**. The system is designed to avoid intrusive exploitation and treats newly discovered assets as candidates until their scope is verified.

AIORI 3 uses cryptographic scope validation to help ensure that monitoring activities operate only within approved targets.

## Presentation

🎥 **YouTube Intro:**  
https://youtu.be/zWLLCSaBG18

## Project Status

Developed as a cybersecurity project addressing:

**Challenge PS-011 — Authorized Attack-Surface Discovery and Monitoring**

## Note

Detection accuracy and security controls should be validated through controlled and authorized testing before production deployment.