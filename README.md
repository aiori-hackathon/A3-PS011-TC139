# 🛡️ Cyber Sentry: AI-Driven External Attack Surface Management (EASM) & Zero-Trust Audit Framework

[![Security Focus](https://img.shields.io/badge/Security-50%25-blue)](https://github.com/Hari3856/Cyber-Sentry)
[![AI Intelligence](https://img.shields.io/badge/AI_%26_Heuristics-30%25-orange)](https://github.com/Hari3856/Cyber-Sentry)
[![Networking Core](https://img.shields.io/badge/Networking-20%25-green)](https://github.com/Hari3856/Cyber-Sentry)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Problem Statement 011 (PS-011)**: Enterprise organizations suffer from uncontrolled scope creep, loud and intrusive scanning tools that trigger IDS/IPS false alarms, and mutable security logs that lack non-repudiation. **Cyber Sentry** solves this through a cryptographic, zero-trust EASM architecture that pairs safe network ingestion with deep cybersecurity risk profiling and immutable audit logging.

---

## 🏛️ System Architecture & Three-Zone Trust Model

Cyber Sentry enforces a strict **Three-Zone Zero-Trust Pipeline** to ensure that all telemetry collection is legally authorized, non-destructive, and cryptographically verifiable:

```text
[ ZONE 1: AUTHORIZATION ]  ---> Asymmetric Ed25519 Scope Signing + Pydantic Schema Validation
           │
           ▼ (Signed Authorization Ticket)
[ ZONE 2: COLLECTION ]     ---> Static IP Pinning, Low-Timeout TCP Probing & x509 TLS Auditing
           │
           ▼ (Raw Canonical Scan Payload)
[ ZONE 3: ANALYTICS & DB ] ---> O(N) State-Drift Engine + SHA-256 Hash-Chained SQLite Ledger ──► Flask SOC UI

🔒 Core Cybersecurity Features & Engineering DepthCyber Sentry is built to satisfy an enterprise-grade 50% Cybersecurity / 30% AI & Heuristics / 20% Networking focus:

1. Cryptographic Scope Enforcement (Zone 1)Mechanism: Prevents unauthorized or malicious scope expansion by requiring an asymmetric Ed25519 digital signature (test_scope.sig) tied to a YAML definition file (test_scope.yaml). If the file is modified or unsigned, the system throws a security exception and fails closed, terminating execution immediately.

2. Safe Network Collector & IP Pinning (Zone 2)Mechanism: Mitigates DNS rebinding and TOCTOU (Time-of-Check to Time-of-Use) attacks by resolving domains to a static IPv4 address prior to execution. Uses non-destructive, low-timeout TCP stream sockets (1.5s timeout via connect_ex()) to check targeted ports without full-port floods or exploit payloads.

3. Service Banner Grabbing & Vulnerability HeuristicsMechanism: Moves beyond binary open/closed status by performing safe socket probes that extract HTTP headers and service software banners (Apache, OpenSSL, custom gateways) to map exposed software versions and identify unencrypted web traffic or exposed databases.

4. CVSS-Style Risk Scoring EngineMechanism: Automatically calculates an Organization Risk Score (0–100) and a security letter grade (A to F) based on weighted asset exposures (e.g., public database ports vs. standard TLS web endpoints).

5. TLS/SSL Certificate Health AuditMechanism: Connects to active HTTPS endpoints to inspect x509 certificates, extracting issuers, calculating days until expiration, and instantly flagging expired or short-lived certificates as CRITICAL or HIGH risks.

6. Shadow-IT & Rogue Subdomain DiscoveryMechanism: Uses high-speed multi-threaded heuristic lookups to surface forgotten developer environments, staging portals, and unmanaged shadow-IT assets (dev., staging., vpn., admin.).

7. Tamper-Evident Hash-Chained Audit Ledger (Zone 3)Mechanism: All scan outcomes, drift events, and risk profiles are logged to an append-only SQLite database using a Merkle-like SHA-256 hash chain ($H_n = \text{SHA256}(\text{Data} \mathbin{\Vert} H_{n-1})$), ensuring absolute non-repudiation for security auditors.

8. Automated SOC Alert DispatcherMechanism: Instantly triggers webhook alerts (Slack/Discord/Teams compatible) upon detecting unexpected infrastructure state drift (e.g., unauthorized ports opening).

9. Cryptographically Signed Compliance Report ExporterMechanism: Generates point-in-time compliance snapshots complete with an integrity verification hash signature for regulatory reporting.🌟 Key Merits & AdvantagesLegal Protection & Compliance: The asymmetric Ed25519 scope authorization guarantees that the organization never steps outside legally authorized scanning boundaries.Non-Destructive Scanning: Unlike aggressive network scanners, Cyber Sentry uses passive banner grabbing and low-impact connection checks, ensuring zero risk of service disruption or IDS/IPS blacklisting.Non-Repudiation: The SHA-256 hash-chained audit ledger guarantees that historical security logs cannot be tampered with or secretly altered by attackers or compromised insiders.Real-Time Operational Visibility: The Flask-powered Security Operations Center (SOC) dashboard provides immediate situational awareness, highlighting risk grades, expiring certificates, and drift alerts in real-time.

📂 Project Directory Structure

Cyber-Sentry/
│
├── core/
│   ├── __init__.py
│   ├── scope_validator.py     # Ed25519 cryptographic scope verification
│   └── risk_engine.py         # CVSS-style risk scoring & org grading
│
├── collectors/
│   ├── __init__.py
│   ├── network_collector.py   # IP-pinned TCP socket probing & banner grabbing
│   ├── tls_collector.py       # x509 certificate auditing & expiry tracking
│   ├── subdomain_enum.py      # Multi-threaded shadow-IT subdomain discovery
│   └── notifier.py            # Automated SOC webhook alert dispatcher
│
├── storage/
│   ├── __init__.py
│   ├── database.py            # SHA-256 hash-chained immutable audit ledger
│   └── exporter.py            # Cryptographically signed compliance report generator
│
├── diff_engine/
│   ├── __init__.py
│   └── analyzer.py            # O(N) differential state-drift engine
│
├── ui/
│   └── app.py                 # Flask cybersecurity dashboard
│
├── test_runner.py             # End-to-end execution pipeline
├── test_scope.yaml            # Authorized target scope definition
├── test_scope.sig             # Ed25519 cryptographic scope signature
└── audit_ledger.db            # Local immutable hash-chained database

🚀 Quickstart & Execution Guide
1. Prerequisites & Installation
Ensure you have Python 3.10+ installed. Install the required security, cryptography, and web dependencies:
pip install pydantic pyyaml cryptography sqlalchemy flask
2. Run the End-to-End Security Pipeline
Execute the main test runner to validate scope signatures, perform network collection, audit TLS health, run state-drift analysis, append blocks to the immutable ledger, and export compliance artifacts:

Bash
python test_runner.py
3. Launch the Security Operations Center (SOC) Dashboard
Start the local WSGI web server to view the real-time risk score, vulnerability breakdown, and shadow-IT infrastructure mapping:

Bash
python ui/app.py
Open your browser and navigate to: http://127.0.0.1:5000

Developed with ❤️ for PS-011 | Team Cyber Sentry