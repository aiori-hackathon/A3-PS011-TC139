import socket
from typing import List, Dict, Any

class SafeNetworkCollector:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def resolve_domain(self, domain: str) -> str:
        """Resolves a hostname to an IPv4 address safely."""
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None

    def probe_ports(self, ip: str, ports: List[int]) -> List[Dict[str, Any]]:
        """
        Safely probes targeted ports on an IP address using low-timeout sockets.
        Guarantees non-disruptive, safe checks.
        """
        results = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Non-destructive connect attempt
            res = sock.connect_ex((ip, port))
            is_open = (res == 0)
            sock.close()

            results.append({
                "port": port,
                "status": "OPEN" if is_open else "CLOSED"
            })
        return results