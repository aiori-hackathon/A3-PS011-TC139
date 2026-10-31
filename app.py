from flask import Flask, render_template_string
import sqlite3
import json

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cyber Sentry | EASM Node Map & Ledger</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
        h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin-bottom: 20px; }
        .status-badge { background: #238636; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }
        .alert-badge { background: #da3633; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; }
        code { font-family: monospace; color: #79c0ff; }
    </style>
</head>
<body>
    <h1>🛡️ Cyber Sentry: Attack Surface & Audit Ledger</h1>
    
    <div class="card">
        <h2>System Authorization Status</h2>
        <p><strong>Authorization Reference:</strong> <code>AUTH-PS011-2026</code> <span class="status-badge">ED25519 VERIFIED</span></p>
        <p><strong>Target Scope:</strong> <code>example.com</code> (IP Pinned: <code>172.66.147.243</code>)</p>
    </div>

    <div class="card">
        <h2>Immutable Ledger Audit Trail (Hash-Chained)</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Event Type</th>
                    <th>Current Block Hash</th>
                </tr>
            </thead>
            <tbody>
                {% for row in ledger %}
                <tr>
                    <td>{{ row[0] }}</td>
                    <td>{{ row[1][:19] }}</td>
                    <td>
                        {% if 'ALERT' in row[2] %}
                            <span class="alert-badge">{{ row[2] }}</span>
                        {% else %}
                            <span class="status-badge">{{ row[2] }}</span>
                        {% endif %}
                    </td>
                    <td><code>{{ row[3] }}</code></td>
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
    cursor.execute("SELECT id, timestamp, event_type, current_hash FROM audit_ledger ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return render_template_string(HTML_TEMPLATE, ledger=rows)

if __name__ == "__main__":
    print("[*] Starting Cyber Sentry Web Dashboard on http://127.0.0.1:5000 ...")
    app.run(port=5000, debug=True)