import sqlite3
import threading
import os

class WorkspaceManager:
def __init__(self, db_path = "~/.omnicore/workspace.db"):
self.db_path = os.path.expanduser(db_path)
os.makedirs(os.path.dirname(self.db_path), exist_ok = True)
self.lock = threading.Lock()
self._init_db()

def _get_connection(self):
"""Internal thread-safe connection factory."""
conn = sqlite3.connect(self.db_path)
conn.row_factory = sqlite3.Row
return conn

def _init_db(self):
"""Enforces a strict, unified database schema across all modules."""
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("""
                    CREATE TABLE IF NOT EXISTS services (
                        ip TEXT,
                        port INTEGER,
                        state TEXT,
                        banner TEXT,
                        PRIMARY KEY (ip, port)
                    )
                """)
cursor.execute("""
                    CREATE TABLE IF NOT EXISTS workspace_snapshots (
                        ip TEXT,
                        port INTEGER,
                        state TEXT,
                        banner TEXT,
                        PRIMARY KEY (ip, port)
                    )
                """)
cursor.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        module TEXT,
                        ip TEXT,
                        category TEXT,
                        data TEXT
                    )
                """)
conn.commit()

def add_service(self, ip, port, state, banner = ""):
"""Public thread-safe method to record or update a service."""
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("""
                    INSERT INTO services (ip, port, state, banner)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ip, port) DO UPDATE SET
                        state = excluded.state,
                        banner = excluded.banner
                """, (ip, port, state, banner))
conn.commit()

def get_services(self):
"""Public thread-safe method returning consistent service records."""
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("SELECT ip, port, state, banner FROM services")
return [dict(row) for row in cursor.fetchall()]

def get_snapshots(self):
"""Public thread-safe method returning baseline snapshot records."""
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("SELECT ip, port, state, banner FROM workspace_snapshots")
return [dict(row) for row in cursor.fetchall()]

def save_snapshot(self):
"""Captures current services into the baseline snapshot table for drift comparison."""
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("DELETE FROM workspace_snapshots")
cursor.execute("""
                    INSERT INTO workspace_snapshots (ip, port, state, banner)
                    SELECT ip, port, state, banner FROM services
                """)
conn.commit()

def add_finding(self, module, ip, category, data_json):
"""Public thread-safe method to log finding payloads."""
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("""
                    INSERT INTO findings (module, ip, category, data)
                    VALUES (?, ?, ?, ?)
                """, (module, ip, category, data_json))
conn.commit()

def get_summary(self):
"""Returns workspace statistics."""
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("SELECT COUNT(DISTINCT ip) as count FROM services")
targets = cursor.fetchone()["count"]
cursor.execute("SELECT COUNT(*) as count FROM services")
services = cursor.fetchone()["count"]
cursor.execute("SELECT COUNT(*) as count FROM findings")
findings = cursor.fetchone()["count"]
return {
    "targets": targets, "services": services, "findings": findings
}

def clear_workspace(self):
"""Resets services and snapshots for clean test execution."""
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("DELETE FROM services")
cursor.execute("DELETE FROM workspace_snapshots")
cursor.execute("DELETE FROM findings")
conn.commit()