import sqlite3
import hashlib
import json
from datetime import datetime

class AppendOnlyLedger:
    def __init__(self, db_path: str = "audit_ledger.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database with a strict ledger schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _get_last_hash(self) -> str:
        """Retrieves the hash of the most recent record, or a default genesis hash."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT current_hash FROM audit_ledger ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else "GENESIS_BLOCK_00000000000000000000000000000000"

    def append_event(self, event_type: str, data: dict) -> str:
        """Appends an event to the ledger with SHA-256 cryptographic chaining."""
        timestamp = datetime.utcnow().isoformat()
        previous_hash = self._get_last_hash()
        data_json = json.dumps(data, sort_keys=True)

        # Generate cryptographic payload hash
        payload = f"{timestamp}|{event_type}|{data_json}|{previous_hash}".encode("utf-8")
        current_hash = hashlib.sha256(payload).hexdigest()

        # Insert as immutable record
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_ledger (timestamp, event_type, data_json, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, event_type, data_json, previous_hash, current_hash))
        conn.commit()
        conn.close()

        print(f"[+] Appended Block #{current_hash[:10]}... | Event: {event_type}")
        return current_hash

    def fetch_all(self):
        """Retrieves all ledger entries."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, event_type, current_hash, previous_hash FROM audit_ledger")
        rows = cursor.fetchall()
        conn.close()
        return rows