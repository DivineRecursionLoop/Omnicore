"""
Workspace Manager - Thread-safe SQLite backend for OmniCore.
Provides centralized persistence for reconnaissance data across all modules.
"""

import sqlite3
import threading
import os


class WorkspaceManager:
    """Thread-safe SQLite database manager for OmniCore workspace persistence."""

    def __init__(self, db_path="~/.omnicore/workspace.db"):
        """
        Initialize workspace manager with SQLite database.
        
        Args:
            db_path (str): Path to SQLite database (default: ~/.omnicore/workspace.db)
        """
        self.db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        """
        Internal thread-safe connection factory.
        
        Returns:
            sqlite3.Connection: Database connection with Row factory enabled
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize and enforce a strict, unified database schema across all modules."""
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

    def add_service(self, ip, port, state, banner=""):
        """
        Record or update a discovered service in thread-safe manner.
        
        Args:
            ip (str): IP address
            port (int): Port number
            state (str): Service state (open, closed, filtered)
            banner (str): Service banner/version info
        """
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
        """
        Retrieve all discovered services in thread-safe manner.
        
        Returns:
            list: List of service dictionaries with keys: ip, port, state, banner
        """
        with self.lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip, port, state, banner FROM services")
                return [dict(row) for row in cursor.fetchall()]

    def get_snapshots(self):
        """
        Retrieve baseline snapshot records in thread-safe manner.
        
        Returns:
            list: List of snapshot dictionaries with keys: ip, port, state, banner
        """
        with self.lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip, port, state, banner FROM workspace_snapshots")
                return [dict(row) for row in cursor.fetchall()]

    def save_snapshot(self):
        """Capture current services state into the baseline snapshot table for drift detection."""
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
        """
        Log a security finding in thread-safe manner.
        
        Args:
            module (str): Module name that generated the finding
            ip (str): IP address associated with finding
            category (str): Finding category/type
            data_json (str): JSON-serialized finding data
        """
        with self.lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO findings (module, ip, category, data)
                    VALUES (?, ?, ?, ?)
                """, (module, ip, category, data_json))
                conn.commit()

    def get_summary(self):
        """
        Get workspace statistics summary.
        
        Returns:
            dict: Dictionary with keys: targets (unique IPs), services (total ports), findings (total findings)
        """
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
                    "targets": targets,
                    "services": services,
                    "findings": findings
                }

    def clear_workspace(self):
        """Reset services, snapshots, and findings for clean test execution."""
        with self.lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM services")
                cursor.execute("DELETE FROM workspace_snapshots")
                cursor.execute("DELETE FROM findings")
                conn.commit()
