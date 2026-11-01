import socket
import ssl
import datetime
from typing import Dict, Any

class TLSCollector:
    @staticmethod
    def inspect_certificate(ip: str, domain: str, port: int = 443) -> Dict[str, Any]:
        """Safely pulls and inspects the TLS/SSL certificate from a target."""
        context = ssl.create_default_context()
        # Do not verify the cert yet; we just want to fetch it to analyze it
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        result = {
            "has_tls": False,
            "issuer": "N/A",
            "days_until_expiry": 0,
            "is_expired": False,
            "risk_level": "INFO"
        }

        try:
            with socket.create_connection((ip, port), timeout=2.0) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    # Load the binary cert using the cryptography library
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    
                    # Extract Issuer
                    issuer = x509_cert.issuer.rfc4514_string()
                    result["issuer"] = issuer.split("CN=")[-1].split(",")[0] if "CN=" in issuer else issuer
                    
                    # Extract Dates
                    not_valid_after = x509_cert.not_valid_after_utc.replace(tzinfo=None)
                    days_remaining = (not_valid_after - datetime.datetime.utcnow()).days
                    
                    result["has_tls"] = True
                    result["days_until_expiry"] = days_remaining
                    result["is_expired"] = days_remaining < 0
                    
                    # Apply Cyber Risk Heuristics for TLS
                    if result["is_expired"]:
                        result["risk_level"] = "CRITICAL"
                    elif days_remaining < 15:
                        result["risk_level"] = "HIGH"
                    else:
                        result["risk_level"] = "LOW"
                        
        except Exception as e:
            result["risk_level"] = "MEDIUM"
            result["issuer"] = "Connection/SSL Handshake Failed"

        return result