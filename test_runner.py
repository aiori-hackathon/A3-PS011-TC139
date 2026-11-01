from cryptography.hazmat.primitives.asymmetric import ed25519
from core.scope_validator import verify_and_load_scope
from storage.database import AppendOnlyLedger
from collectors.network_collector import SafeNetworkCollector
from diff_engine.analyzer import DifferentialEngine
from core.risk_engine import RiskEngine   
from collectors.tls_collector import TLSCollector
from collectors.subdomain_enum import SubdomainEnumerator
from collectors.notifier import AlertDispatcher
from storage.exporter import ReportExporter
import yaml


def generate_scope_files() -> str:
    """Generate an Ed25519-signed sample scope and return the public key hex."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_hex = public_key.public_bytes_raw().hex()

    scope_data = {
        "scope_version": 1,
        "owner": "AIORI Hackathon Team",
        "authorization_ref": "AUTH-PS011-2026",
        "valid_from": "2026-10-01",
        "valid_until": "2026-12-31",
        "domains": [{"name": "example.com", "include_subdomains": True}],
    }

    scope_bytes = yaml.safe_dump(scope_data).encode("utf-8")
    signature_bytes = private_key.sign(scope_bytes)

    with open("test_scope.yaml", "wb") as f:
        f.write(scope_bytes)
    with open("test_scope.sig", "w", encoding="utf-8") as f:
        f.write(signature_bytes.hex())

    return public_key_hex


def main() -> None:
    public_key_hex = generate_scope_files()

    print("\n==========================================")
    print("[STEP 1] Validating Cryptographic Scope...")
    print("==========================================")
    verified_scope = verify_and_load_scope(
        scope_file_path="test_scope.yaml",
        signature_file_path="test_scope.sig",
        public_key_hex=public_key_hex,
    )

    ledger = AppendOnlyLedger()
    collector = SafeNetworkCollector(timeout=1.5)

    target_domain = verified_scope.domains[0].name
    ip = collector.resolve_domain(target_domain)
    if ip is None:
        raise RuntimeError(f"Unable to resolve target domain: {target_domain}")

    print("\n==========================================")
    print("[STEP 2.5] Shadow-IT Subdomain Discovery...")
    print("==========================================")
    enumerator = SubdomainEnumerator(target_domain)
    subdomains = enumerator.discover()
    
    print(f"[+] Discovered {len(subdomains)} active endpoints:")
    for sub in subdomains:
        print(f"    - {sub['subdomain']} -> [IP: {sub['ip']}] ({sub['type']})")

    print("\n==========================================")
    print("[STEP 3] Running Network Collector...")
    print("==========================================")
    current_scan = collector.probe_ports(ip, [80, 443, 8080, 22, 3306])

    print(f"[+] Security Profiling for {ip}:")
    for res in current_scan:
        if res["status"] == "OPEN":
            print(f"    [!] Port {res['port']} ({res['service']}) - Risk: {res['risk_level']}")
            print(f"        Issue: {res['security_issue']}")
            print(f"        Banner: {res['banner']}")
        else:
            print(f"    [-] Port {res['port']} - CLOSED")

    print("\n==========================================")
    print("[STEP 3.5] Inspecting TLS/SSL Certificates...")
    print("==========================================")
    tls_data = None
    if any(res["port"] == 443 and res["status"] == "OPEN" for res in current_scan):
        tls_data = TLSCollector.inspect_certificate(ip, target_domain)
        print(f"[+] TLS Certificate Profile for {target_domain}:")
        print(f"    Issuer: {tls_data['issuer']}")
        print(f"    Days Until Expiry: {tls_data['days_until_expiry']}")
        print(f"    Status: {'EXPIRED' if tls_data['is_expired'] else 'VALID'} - Risk: {tls_data['risk_level']}")
    else:
        print("[-] Port 443 closed or unavailable. Skipping TLS inspection.")

    print("\n==========================================")
    print("[STEP 4] Differential Analysis Engine...")
    print("==========================================")
    baseline_scan = [
        {"port": 80, "status": "OPEN"},
        {"port": 443, "status": "OPEN"},
        {"port": 8080, "status": "CLOSED"},
        {"port": 22, "status": "CLOSED"},
    ]
    diff_result = DifferentialEngine.compare_states(baseline_scan, current_scan)

    if diff_result["has_changes"]:
        print("    [!] DRIFT DETECTED!")
        print(f"    [ALERT] Newly Opened Ports: {diff_result['newly_opened_ports']}")

        dispatcher = AlertDispatcher()
        dispatcher.send_drift_alert(target_domain, diff_result)

        hash_val = ledger.append_event("STATE_DRIFT_ALERT", diff_result)
        print(f"    [+] Appended Block #{hash_val[:12]}... | Event: STATE_DRIFT_ALERT")
    else:
        print("    [+] No state drift detected. Infrastructure matches baseline.")

    print("\n==========================================")
    print("[STEP 2] Logging Run Output to DB...")
    print("==========================================")

    # Calculate overall risk
    risk_profile = RiskEngine.calculate_org_risk(current_scan)
    print(f"[+] Organization Grade: {risk_profile['overall_grade']} | Score: {risk_profile['aggregate_score']}/100")

    # Log the scan with all cybersecurity contexts
    ledger.append_event("SCAN_COMPLETED", {
        "domain": target_domain, 
        "ip": ip, 
        "scan": current_scan,
        "risk_profile": risk_profile,
        "tls_profile": tls_data,
        "shadow_assets": subdomains
    })

    print("\n[+] Final Audit Ledger Summary:")
    for row in ledger.fetch_all():
        print(f"    ID: {row[0]} | Time: {row[1][:19]} | Event: {row[2]} | Hash: {row[3][:16]}...")
    print("\n==========================================")
    print("[STEP 5] Generating Compliance Report...")
    print("==========================================")
    exporter = ReportExporter()
    report_file = exporter.generate_compliance_report()
    print(f"[+] Cryptographically signed compliance report saved to: {report_file}")


if __name__ == "__main__":
    main()
