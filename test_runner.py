<<<<<<< HEAD
from cryptography.hazmat.primitives.asymmetric import ed25519
from core.scope_validator import verify_and_load_scope
from storage.database import AppendOnlyLedger
from collectors.network_collector import SafeNetworkCollector
from diff_engine.analyzer import DifferentialEngine
import yaml

# 1. Setup Keys & Scope
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()
public_key_hex = public_key.public_bytes_raw().hex()

scope_data = {
    "scope_version": 1,
    "owner": "AIORI Hackathon Team",
    "authorization_ref": "AUTH-PS011-2026",
    "valid_from": "2026-10-01",
    "valid_until": "2026-12-31",
    "domains": [{"name": "example.com", "include_subdomains": True}]
}

scope_bytes = yaml.safe_dump(scope_data).encode("utf-8")
signature_bytes = private_key.sign(scope_bytes)

with open("test_scope.yaml", "wb") as f:
    f.write(scope_bytes)
with open("test_scope.sig", "w") as f:
    f.write(signature_bytes.hex())

if __name__ == "__main__":
    print("\n==========================================")
    print("[STEP 1] Validating Cryptographic Scope...")
    print("==========================================")
    verified_scope = verify_and_load_scope(
        scope_file_path="test_scope.yaml",
        signature_file_path="test_scope.sig",
        public_key_hex=public_key_hex
    )

    ledger = AppendOnlyLedger()
    collector = SafeNetworkCollector(timeout=1.5)
    
    target_domain = verified_scope.domains[0].name
    ip = collector.resolve_domain(target_domain)

    print("\n==========================================")
    print("[STEP 3] Running Network Collector...")
    print("==========================================")
    current_scan = collector.probe_ports(ip, [80, 443, 8080, 22])
    print(f"[+] Current Scan State for {ip}: {current_scan}")

    print("\n==========================================")
    print("[STEP 4] Differential Analysis Engine...")
    print("==========================================")
    # Simulated baseline where port 8080 was previously CLOSED
    baseline_scan = [
        {"port": 80, "status": "OPEN"},
        {"port": 443, "status": "OPEN"},
        {"port": 8080, "status": "CLOSED"},
        {"port": 22, "status": "CLOSED"}
    ]

    diff = DifferentialEngine.compare_states(baseline_scan, current_scan)
    if diff["has_changes"]:
        print(f"[!] DRIFT DETECTED!")
        if diff["newly_opened_ports"]:
            print(f"    [ALERT] Newly Opened Ports: {diff['newly_opened_ports']}")
        if diff["newly_closed_ports"]:
            print(f"    [INFO] Newly Closed Ports: {diff['newly_closed_ports']}")
        
        ledger.append_event("STATE_DRIFT_ALERT", diff)
    else:
        print("[+] No state drift detected. Current state matches baseline.")

    print("\n==========================================")
    print("[STEP 2] Logging Run Output to DB...")
    print("==========================================")
    ledger.append_event("SCAN_COMPLETED", {"domain": target_domain, "ip": ip, "scan": current_scan})

    print("\n[+] Final Audit Ledger Summary:")
    for row in ledger.fetch_all():
=======
from cryptography.hazmat.primitives.asymmetric import ed25519
from core.scope_validator import verify_and_load_scope
from storage.database import AppendOnlyLedger
from collectors.network_collector import SafeNetworkCollector
from diff_engine.analyzer import DifferentialEngine
import yaml

# 1. Setup Keys & Scope
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()
public_key_hex = public_key.public_bytes_raw().hex()

scope_data = {
    "scope_version": 1,
    "owner": "AIORI Hackathon Team",
    "authorization_ref": "AUTH-PS011-2026",
    "valid_from": "2026-10-01",
    "valid_until": "2026-12-31",
    "domains": [{"name": "example.com", "include_subdomains": True}]
}

scope_bytes = yaml.safe_dump(scope_data).encode("utf-8")
signature_bytes = private_key.sign(scope_bytes)

with open("test_scope.yaml", "wb") as f:
    f.write(scope_bytes)
with open("test_scope.sig", "w") as f:
    f.write(signature_bytes.hex())

if __name__ == "__main__":
    print("\n==========================================")
    print("[STEP 1] Validating Cryptographic Scope...")
    print("==========================================")
    verified_scope = verify_and_load_scope(
        scope_file_path="test_scope.yaml",
        signature_file_path="test_scope.sig",
        public_key_hex=public_key_hex
    )

    ledger = AppendOnlyLedger()
    collector = SafeNetworkCollector(timeout=1.5)
    
    target_domain = verified_scope.domains[0].name
    ip = collector.resolve_domain(target_domain)

    print("\n==========================================")
    print("[STEP 3] Running Network Collector...")
    print("==========================================")
    current_scan = collector.probe_ports(ip, [80, 443, 8080, 22])
    print(f"[+] Current Scan State for {ip}: {current_scan}")

    print("\n==========================================")
    print("[STEP 4] Differential Analysis Engine...")
    print("==========================================")
    # Simulated baseline where port 8080 was previously CLOSED
    baseline_scan = [
        {"port": 80, "status": "OPEN"},
        {"port": 443, "status": "OPEN"},
        {"port": 8080, "status": "CLOSED"},
        {"port": 22, "status": "CLOSED"}
    ]

    diff = DifferentialEngine.compare_states(baseline_scan, current_scan)
    if diff["has_changes"]:
        print(f"[!] DRIFT DETECTED!")
        if diff["newly_opened_ports"]:
            print(f"    [ALERT] Newly Opened Ports: {diff['newly_opened_ports']}")
        if diff["newly_closed_ports"]:
            print(f"    [INFO] Newly Closed Ports: {diff['newly_closed_ports']}")
        
        ledger.append_event("STATE_DRIFT_ALERT", diff)
    else:
        print("[+] No state drift detected. Current state matches baseline.")

    print("\n==========================================")
    print("[STEP 2] Logging Run Output to DB...")
    print("==========================================")
    ledger.append_event("SCAN_COMPLETED", {"domain": target_domain, "ip": ip, "scan": current_scan})

    print("\n[+] Final Audit Ledger Summary:")
    for row in ledger.fetch_all():
>>>>>>> 9b9e1fd (Initial commit)
        print(f"    ID: {row[0]} | Time: {row[1][:19]} | Event: {row[2]} | Hash: {row[3][:16]}...")