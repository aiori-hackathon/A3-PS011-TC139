import json
import urllib.request
from typing import Dict, Any

class AlertDispatcher:
    def __init__(self, webhook_url: str = None):
        # For the hackathon, we simulate the webhook unless a real URL is provided.
        self.webhook_url = webhook_url

    def send_drift_alert(self, domain: str, diff_data: Dict[str, Any]) -> bool:
        """Dispatches a high-priority alert when infrastructure drift is detected."""
        if not diff_data.get("has_changes"):
            return False

        new_ports = diff_data.get('newly_opened_ports', [])
        
        payload = {
            "content": f"🚨 **CYBER SENTRY ALERT: STATE DRIFT DETECTED** 🚨\n"
                       f"**Target Scope:** `{domain}`\n"
                       f"**Security Event:** Unexpected port exposure detected.\n"
                       f"**Newly Opened Ports:** `{new_ports}`\n"
                       f"**Action Required:** Immediate review by Security Operations."
        }
        
        print("\n[!] [WEBHOOK ENGINE] Dispatching alert to Security Operations Center...")
        
        if self.webhook_url:
            try:
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(
                    self.webhook_url, 
                    data=data, 
                    headers={'Content-Type': 'application/json', 'User-Agent': 'CyberSentry-Bot'}
                )
                urllib.request.urlopen(req, timeout=3)
                print("    -> Alert successfully delivered to webhook endpoint.")
            except Exception as e:
                print(f"    -> Webhook delivery failed: {e}")
        else:
            print("    -> [Simulation Mode] Webhook URL not set. Logging payload to console:")
            safe_content = payload["content"].encode("ascii", "replace").decode("ascii")
            print(f"       Payload Data: {safe_content}")

        return True