import json
from base_module import BaseModule

class ModuleDefinition(BaseModule):
name = "privilege_escalation_pathfinder"
description = "Models discovered workspace services into local and lateral movement pivot chains."

def __init__(self):
super().__init__()
self.options = {
    "TARGET_IP": {
        "value": "AUTO",
        "required": True,
        "description": "Use 'AUTO' to analyze all workspace nodes, or specify a single IP address"
    },
    "OUTPUT_FILE": {
        "value": "pivot_matrix_report.json",
        "required": False,
        "description": "Filename to export JSON lateral movement and escalation matrix"
    }
}

# Heuristic rulebook mapping combination vectors to operational pivot strategies
self.pivot_rules = [{
    "trigger_ports": [22],
    "context": "SSH Service Available",
    "local_vector": "Check for weak user passwords, authorized_keys misconfigurations, or sudo rights.",
    "pivot_value": "High-value administrative access point for lateral tunneling (ssh -D / -L)."
},
    {
        "trigger_ports": [445],
        "context": "SMB / Common File Sharing Exposed",
        "local_vector": "Inspect for null sessions, SMB signing disabled, or SMBv1/v2 execution vulnerabilities.",
        "pivot_value": "Prime vector for credential dumping (Responder/secretsdump) and lateral worming."
    },
    {
        "trigger_ports": [3306],
        "context": "MySQL Database Service Exposed",
        "local_vector": "Check for root:blank credentials, UDF code execution, or SELECT INTO OUTFILE web shell writes.",
        "pivot_value": "Data exfiltration node or potential stepping stone to local OS command execution."
    },
    {
        "trigger_ports": [80, 443, 8080, 8443],
        "context": "Web Application Surface",
        "local_vector": "Scan for default administrative dashboards, exposed git folders, or remote code execution flaws.",
        "pivot_value": "Initial user execution context; inspect cookies/config files for database or API credentials."
    }]

def run(self):
target_input = self.options["TARGET_IP"]["value"].strip()
output_file = self.options["OUTPUT_FILE"]["value"]

print("[*] Querying OmniCore workspace database for topology and service mapping...")
services = self.workspace.get_services()

if not services:
print("[!] Error: No services found in the workspace database.")
print("[!] Tip: Run the 'port_scanner' module first to map out active host ports.")
return

# Filter services if a specific target IP was provided
if target_input.upper() != "AUTO":
services = [s for s in services if s["ip"] == target_input]
if not services:
print(f"[!] No services found in workspace for IP: {
    target_input
}")
return

# Group services by target IP address to build host profiles
hosts = {}
for svc in services:
ip = svc["ip"]
if ip not in hosts:
hosts[ip] = []
hosts[ip].append(svc)

print(f"\n[*] Modeling attack paths across {
    len(hosts)} host(s)...")
print("=" * 75)

operational_matrices = []

for ip, host_services in hosts.items():
open_ports = [s["port"] for s in host_services if s["state"].upper() == "OPEN"]
print(f"\n[*] Target Node: {
    ip
}")
print(f"    Open Ports: {
    open_ports
}")

host_findings = []

# Evaluate heuristic pivot rules against the host's open ports
for rule in self.pivot_rules:
matching_ports = [p for p in rule["trigger_ports"] if p in open_ports]
if matching_ports:
print(f"    [+] Vector Match [ {
    rule['context']}]: Ports {
    matching_ports
}")
print(f"        -> Local Vector : {
    rule['local_vector']}")
print(f"        -> Pivot Value  : {
    rule['pivot_value']}")

host_findings.append({
    "context": rule["context"],
    "matching_ports": matching_ports,
    "local_vector": rule["local_vector"],
    "pivot_value": rule["pivot_value"]
})

# Compound chain logic (e.g., Web + Database on the same host)
compound_chain = None
if any(p in open_ports for p in [80, 443, 8080, 8443]) and 3306 in open_ports:
compound_chain = "High Confidence Chain: Web Application interface coupled with direct Database exposure. Compromise web context to query internal database tables or leverage SQLi for file writing."
print(f"    [!] CHAIN IDENTIFIED: {
    compound_chain
}")

node_report = {
    "ip": ip,
    "open_ports": open_ports,
    "vectors": host_findings,
    "compound_attack_chain": compound_chain
}
operational_matrices.append(node_report)
print("-" * 75)

print(f"[*] Pathfinding analysis complete. Generated operational matrix for {
    len(operational_matrices)} host(s).")

# Sync matrix back into workspace findings table
try:
with self.workspace._lock:
with self.workspace._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("""
                        INSERT INTO findings (module, ip, category, data)
                        VALUES (?, ?, ?, ?)
                    """, (self.name, "GLOBAL", "PIVOT_PATHWAY_MATRIX", json.dumps(operational_matrices)))
conn.commit()
except Exception:
pass

# Export JSON report if requested
if output_file and operational_matrices:
self.export_json(operational_matrices, filename = output_file)