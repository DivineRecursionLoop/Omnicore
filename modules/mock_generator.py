from base_module import BaseModule

class ModuleDefinition(BaseModule):
name = "mock_generator"
description = "Populates the SQLite workspace with realistic sample network telemetry using public WorkspaceManager methods."

def __init__(self):
super().__init__()
self.options = {
    "HOST_COUNT": {
        "value": "5",
        "required": False,
        "description": "Number of synthetic hosts to generate"
    }
}

def run(self):
print("[*] Generating synthetic network workspace telemetry via WorkspaceManager API...")

try:
self.workspace.clear_workspace()

mock_services = [
    ("192.168.1.1", 22, "OPEN", "ssh"),
    ("192.168.1.1", 80, "OPEN", "http"),
    ("192.168.1.10", 22, "OPEN", "ssh"),
    ("192.168.1.10", 80, "OPEN", "http"),
    ("192.168.1.10", 445, "OPEN", "microsoft-ds"),
    ("192.168.1.10", 3389, "OPEN", "ms-wbt-server"),
    ("192.168.1.45", 80, "OPEN", "http"),
    ("192.168.1.45", 443, "OPEN", "https"),
    ("192.168.1.45", 3306, "OPEN", "mysql"),
    ("192.168.1.100", 5432, "OPEN", "postgresql"),
    ("192.168.1.100", 6379, "OPEN", "redis"),
    ("192.168.1.200", 8080, "OPEN", "http-proxy")
]

for ip, port, state, banner in mock_services:
self.workspace.add_service(ip, port, state, banner)

with self.workspace.lock, self.workspace._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("DELETE FROM workspace_snapshots")
for ip, port, state, banner in mock_services:
if port == 8080:
continue
cursor.execute(
    "INSERT INTO workspace_snapshots (ip, port, state, banner) VALUES (?, ?, ?, ?)",
    (ip, port, state, banner)
)
conn.commit()

print("[+] Successfully seeded mock workspace database via unified API!")
except Exception as e:
print(f"[!] Error seeding mock data: {
    e
}")