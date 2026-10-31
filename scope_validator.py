import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel
from typing import List

class DomainRule(BaseModel):
    name: str
    include_subdomains: bool = True

class ScopeSchema(BaseModel):
    scope_version: int
    owner: str
    authorization_ref: str
    valid_from: str
    valid_until: str
    domains: List[DomainRule]

def verify_and_load_scope(scope_file_path: str, signature_file_path: str, public_key_hex: str) -> ScopeSchema:
    # 1. Load public key
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    except Exception as e:
        raise ValueError(f"Invalid public key format: {e}")

    # 2. Read scope and signature bytes
    with open(scope_file_path, "rb") as f:
        scope_bytes = f.read()
        
    with open(signature_file_path, "rb") as f:
        signature_bytes = bytes.fromhex(f.read().strip().decode())

    # 3. Verify cryptographic signature (Ed25519)
    try:
        public_key.verify(signature_bytes, scope_bytes)
        print("[+] SUCCESS: Cryptographic signature verified successfully!")
    except InvalidSignature:
        raise PermissionError("[-] CRITICAL: Scope file signature verification FAILED. Refusing to run.")

    # 4. Safe YAML load & Pydantic Schema Validation
    raw_data = yaml.safe_load(scope_bytes)
    scope = ScopeSchema(**raw_data)
    
    return scope