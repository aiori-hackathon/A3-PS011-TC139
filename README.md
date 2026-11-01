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