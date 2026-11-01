import sqlite3
import json
import datetime
import hashlib
import os

class ReportExporter:
    def __init__(self, db_path: str = "audit_ledger.db"):
        self.db_path = db_path

    def generate_compliance_report(self) -> str:
        """Generates a cryptographically signed compliance report from the ledger."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Fetch the most recent SCAN_COMPLETED event
        cursor.execute("SELECT id, timestamp, data_json, current_hash FROM audit_ledger WHERE event_type = 'SCAN_COMPLETED' ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        if not row:
            return "No scan data available to export."

        block_id, timestamp, data_json, current_hash = row
        data = json.loads(data_json)
        
        domain = data.get("domain", "Unknown")
        risk_profile = data.get("risk_profile", {})
        tls_profile = data.get("tls_profile", {})
        assets = [p for p in data.get("scan", []) if p.get("status") == "OPEN"]
        shadow_assets = data.get("shadow_assets", [])

        # Build the report string
        report_lines = [
            "=" * 60,
            f"CYBER SENTRY - EASM COMPLIANCE REPORT",
            "=" * 60,
            f"Target Scope      : {domain}",
            f"Scan Timestamp    : {timestamp}",
            f"Ledger Block ID   : {block_id}",
            f"Block Hash        : {current_hash}",
            "-" * 60,
            f"ORGANIZATION RISK SCORE : {risk_profile.get('aggregate_score', 0)}/100",
            f"OVERALL GRADE           : {risk_profile.get('overall_grade', 'N/A')}",
            "-" * 60,
            "TLS CERTIFICATE HEALTH:",
        ]

        if tls_profile and tls_profile.get("has_tls"):
            report_lines.append(f"  Issuer      : {tls_profile.get('issuer')}")
            report_lines.append(f"  Expiry      : {tls_profile.get('days_until_expiry')} days")
            report_lines.append(f"  Risk Level  : {tls_profile.get('risk_level')}")
        else:
            report_lines.append("  No TLS data available.")

        report_lines.extend(["-" * 60, "EXPOSED ASSET VULNERABILITY PROFILE:"])
        for asset in assets:
            report_lines.append(f"  [+] Port {asset['port']} ({asset['service']}) - Risk: {asset['risk_level']}")
            report_lines.append(f"      Issue: {asset['security_issue']}")

        report_lines.extend(["-" * 60, "SHADOW-IT / DISCOVERED INFRASTRUCTURE:"])
        for sa in shadow_assets:
            report_lines.append(f"  [*] {sa['subdomain']} -> {sa['ip']} ({sa['type']})")

        # Create a cryptographic signature of the report contents
        report_content = "\n".join(report_lines)
        signature = hashlib.sha256(report_content.encode('utf-8')).hexdigest()
        
        report_lines.extend([
            "-" * 60,
            f"REPORT INTEGRITY SIGNATURE (SHA-256):",
            f"{signature}",
            "=" * 60,
            "END OF REPORT"
        ])

        final_report = "\n".join(report_lines)
        
        # Save to file
        filename = f"Compliance_Report_{domain}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(final_report)

        return filename