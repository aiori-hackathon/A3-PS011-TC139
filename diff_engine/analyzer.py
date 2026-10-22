from typing import List, Dict, Any

class DifferentialEngine:
    @staticmethod
    def compare_states(previous_ports: List[Dict[str, Any]], current_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compares current port scan results with the previous baseline scan
        to detect infrastructure changes (drift).
        """
        prev_map = {p["port"]: p["status"] for p in previous_ports}
        curr_map = {p["port"]: p["status"] for p in current_ports}

        newly_opened = []
        newly_closed = []

        for port, status in curr_map.items():
            prev_status = prev_map.get(port, "CLOSED")
            if status == "OPEN" and prev_status != "OPEN":
                newly_opened.append(port)
            elif status == "CLOSED" and prev_status == "OPEN":
                newly_closed.append(port)

        return {
            "has_changes": len(newly_opened) > 0 or len(newly_closed) > 0,
            "newly_opened_ports": newly_opened,
            "newly_closed_ports": newly_closed
        }