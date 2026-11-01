import socket
from typing import List, Dict, Any

# Cybersecurity Risk Knowledge Base
PORT_RISK_MAP = {
    21: {"service": "FTP", "risk": "HIGH", "issue": "Cleartext protocol, highly vulnerable"},
    22: {"service": "SSH", "risk": "MEDIUM", "issue": "Potential brute-force target"},
    80: {"service": "HTTP", "risk": "MEDIUM", "issue": "Unencrypted web traffic"},
    443: {"service": "HTTPS", "risk": "LOW", "issue": "Standard encrypted web"},
    3306: {"service": "MySQL", "risk": "CRITICAL", "issue": "Database exposed to public internet"},
    8080: {"service": "HTTP-Alt", "risk": "MEDIUM", "issue": "Often used for dev/admin panels"}
}

class SafeNetworkCollector:
    def __init__(self, timeout: float = 1.5):
        self.timeout = timeout

    def resolve_domain(self, domain: str) -> str:
        """Resolves a hostname to an IPv4 address safely."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def grab_banner(self, ip: str, port: int) -> str:
        """Safely extracts the service banner to identify software versions."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Send a basic HTTP probe for web ports to trigger a response
            if port in [80, 8080, 443]:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Return just the first line of the server response
            if banner:
                return banner.split('\n')[0][:60]
            return "No banner returned"
        except Exception:
            return "Banner grab timeout/failed"

    def probe_ports(self, ip: str, ports: List[int]) -> List[Dict[str, Any]]:
        """Probes ports and attaches cybersecurity risk context."""
        results = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            res = sock.connect_ex((ip, port))
            sock.close()

            is_open = (res == 0)
            
            # 1. Grab the banner if the port is open
            banner = self.grab_banner(ip, port) if is_open else None
            
            # 2. Assign Cybersecurity Risk Context
            context = PORT_RISK_MAP.get(port, {"service": "Unknown", "risk": "INFO", "issue": "Unmapped port"})

            results.append({
                "port": port,
                "status": "OPEN" if is_open else "CLOSED",
                "service": context["service"],
                "risk_level": context["risk"] if is_open else "NONE",
                "security_issue": context["issue"] if is_open else "N/A",
                "banner": banner
            })
        return results