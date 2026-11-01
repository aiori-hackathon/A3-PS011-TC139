from flask import Flask, render_template_string
import sqlite3
import json

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cyber Sentry | EASM Security Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
        h1, h2, h3 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-top: 0;}
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin-bottom: 20px; }
        .flex-container { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap;}
        .box { flex: 1; min-width: 250px; padding: 15px; background: #21262d; border-radius: 6px; border: 1px solid #30363d; text-align: center; }
        .status-badge { background: #238636; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }
        .alert-badge { background: #da3633; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }
        .med-badge { background: #d29922; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }
        code { font-family: monospace; color: #79c0ff; }
        .score-text { font-size: 2em; font-weight: bold; margin: 10px 0; color: #da3633; }
        .text-left { text-align: left; }
    </style>
</head>
<body>
    <h1>🛡️ Cyber Sentry: Attack Surface Management</h1>
    
    <div class="flex-container">
        <!-- Target Info -->
        <div class="box">
            <h3>Target Scope</h3>
            <p><code>example.com</code></p>
            <p>IP Pinned: <code>172.66.147.243</code></p>
            <p><span class="status-badge">ED25519 VERIFIED</span></p>
        </div>
        
        <!-- Risk Score -->
        <div class="box">
            <h3>Organization Risk Score</h3>
            <div class="score-text">{{ risk_data.aggregate_score }}/100</div>
            <p>{{ risk_data.overall_grade }}</p>
        </div>
        
        <!-- TLS Certificate Health -->
        <div class="box text-left">
            <h3 style="text-align: center;">TLS Certificate Health</h3>
            {% if tls_data and tls_data.has_tls %}
                <p><strong>Issuer:</strong> <code>{{ tls_data.issuer }}</code></p>
                <p><strong>Expires In:</strong> {{ tls_data.days_until_expiry }} days</p>
                <p style="text-align: center;">
                    {% if tls_data.risk_level == 'CRITICAL' %}
                        <span class="alert-badge">EXPIRED (CRITICAL)</span>
                    {% elif tls_data.risk_level == 'HIGH' %}
                        <span class="med-badge">EXPIRING SOON</span>
                    {% else %}
                        <span class="status-badge">VALID & SECURE</span>
                    {% endif %}
                </p>
            {% else %}
                <p style="text-align: center; color: #8b949e;">No TLS Data Available</p>
            {% endif %}
        </div>
    </div>

    <div class="card">
        <h2>Discovered Infrastructure (Shadow-IT Mapping)</h2>
        <table>
            <thead>
                <tr>
                    <th>Subdomain / Asset</th>
                    <th>Resolved IP</th>
                    <th>Asset Type</th>
                </tr>
            </thead>
            <tbody>
                {% for asset in shadow_assets %}
                <tr>
                    <td><code>{{ asset.subdomain }}</code></td>
                    <td><code>{{ asset.ip }}</code></td>
                    <td>
                        {% if asset.type == 'SHADOW ASSET' %}
                            <span class="alert-badge">{{ asset.type }}</span>
                        {% else %}
                            <span class="status-badge">{{ asset.type }}</span>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr><td colspan="3" style="text-align: center; color: #8b949e;">No additional infrastructure discovered in this scan.</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Live Asset Vulnerability Profile</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Risk Level</th>
                    <th>Security Context</th>
                    <th>Service Banner</th>
                </tr>
            </thead>
            <tbody>
                {% for asset in assets %}
                <tr>
                    <td><code>{{ asset.port }}</code></td>
                    <td>{{ asset.service }}</td>
                    <td>
                        {% if asset.risk_level == 'CRITICAL' or asset.risk_level == 'HIGH' %}
                            <span class="alert-badge">{{ asset.risk_level }}</span>
                        {% elif asset.risk_level == 'MEDIUM' %}
                            <span class="med-badge">{{ asset.risk_level }}</span>
                        {% else %}
                            <span class="status-badge">{{ asset.risk_level }}</span>
                        {% endif %}
                    </td>
                    <td>{{ asset.security_issue }}</td>
                    <td><code>{{ asset.banner }}</code></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

@app.route("/")
def dashboard():
    conn = sqlite3.connect("audit_ledger.db")
    cursor = conn.cursor()
    cursor.execute("SELECT data_json FROM audit_ledger WHERE event_type = 'SCAN_COMPLETED' ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()

    assets = []
    shadow_assets = []
    risk_data = {"aggregate_score": 0, "overall_grade": "N/A"}
    tls_data = None
    
    if row:
        data = json.loads(row[0])
        assets = [port for port in data.get("scan", []) if port.get("status") == "OPEN"]
        shadow_assets = data.get("shadow_assets", [])
        risk_data = data.get("risk_profile", risk_data)
        tls_data = data.get("tls_profile", None)

    return render_template_string(HTML_TEMPLATE, assets=assets, shadow_assets=shadow_assets, risk_data=risk_data, tls_data=tls_data)

if __name__ == "__main__":
    app.run(port=5000, debug=True)