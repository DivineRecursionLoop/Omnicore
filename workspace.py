import sqlite3
import os
import threading

class WorkspaceManager:
def __init__(self, db_name = "omnicore_workspace.db"):
# Professional Polish: Store workspace database in ~/.omnicore/ directory
self.config_dir = os.path.expanduser("~/.omnicore")
if not os.path.exists(self.config_dir):
os.makedirs(self.config_dir, exist_ok = True)

self.db_path = os.path.join(self.config_dir, db_name)
self.lock = threading.Lock()
self._init_db()

def _get_connection(self):
conn = sqlite3.connect(self.db_path)
conn.row_factory = sqlite3.Row
return conn

def _init_db(self):
"""Creates core tables with thread safety guarantees."""
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()

cursor.execute("""
                    CREATE TABLE IF NOT EXISTS targets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT UNIQUE,
                        hostname TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

cursor.execute("""
                    CREATE TABLE IF NOT EXISTS services (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT,
                        port INTEGER,
                        protocol TEXT DEFAULT 'tcp',
                        state TEXT,
                        banner TEXT,
                        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(ip, port)
                    )
                """)

cursor.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        module TEXT,
                        ip TEXT,
                        category TEXT,
                        data TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
conn.commit()

def add_target(self, ip, hostname = ""):
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("""
                    INSERT INTO targets (ip, hostname) VALUES (?, ?)
                    ON CONFLICT(ip) DO UPDATE SET hostname = COALESCE(NULLIF(?, ''), hostname)
                """, (ip, hostname, hostname))
conn.commit()

def add_service(self, ip, port, state = "OPEN", banner = "N/A", protocol = "tcp"):
self.add_target(ip)
with self.lock:
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("""
                    INSERT INTO services (ip, port, protocol, state, banner)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(ip, port) DO UPDATE SET state = ?, banner = ?
                """, (ip, port, protocol, state, banner, state, banner))
conn.commit()

def get_services(self, port = None):
with self._get_connection() as conn:
cursor = conn.cursor()
if port:
cursor.execute("SELECT * FROM services WHERE port = ?", (port,))
else :
cursor.execute("SELECT * FROM services")
return [dict(row) for row in cursor.fetchall()]

def get_summary(self):
with self._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) as count FROM targets")
targets_count = cursor.fetchone()["count"]

cursor.execute("SELECT COUNT(*) as count FROM services")
services_count = cursor.fetchone()["count"]

cursor.execute("SELECT COUNT(*) as count FROM findings")
findings_count = cursor.fetchone()["count"]

return {
    "targets": targets_count, "services": services_count, "findings": findings_count
}