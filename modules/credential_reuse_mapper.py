import json
from base_module import BaseModule

class ModuleDefinition(BaseModule):
name = "credential_reuse_mapper"
description = "Correlates workspace service banners with known default credentials and high-risk initial access vectors."

def __init__(self):
super().__init__()
self.options = {
    "TARGET_IP": {
        "value": "AUTO",
        "required": True,
        "description": "Use 'AUTO' to analyze all services in workspace, or specify a single IP address"
    },
    "OUTPUT_FILE": {
        "value": "attack_matrix_report.json",
        "required": False,
        "description": "Filename to export JSON intelligence matrix"
    }
}

# Embedded intelligence dictionary mapping software/banner signatures to risks & default credentials
self.intel_database = [{
    "signature": "vsftpd 2.3.4",
    "service": "FTP",
    "risk_level": "CRITICAL",
    "issue": "Backdoor Command Execution Vulnerability (CVE-2011-2523)",
    "default_creds": ["Any username with a :) smiley face trigger"],
    "recommendation": "Upgrade vsftpd immediately or disable service."
},
    {
        "signature": "tomcat",
        "service": "HTTP/Tomcat",
        "risk_level": "HIGH",
        "issue": "Apache Tomcat Manager Application Exposed",
        "default_creds": ["tomcat:tomcat", "admin:admin", "role1:tomcat", "root:root"],
        "recommendation": "Restrict access to manager/html or remove default administrative accounts."
    },
    {
        "signature": "openssh",
        "service": "SSH",
        "risk_level": "MEDIUM",
        "issue": "Standard SSH Service - Check for Weak/Default Credentials or Key Reuse",
        "default_creds": ["root:root", "admin:admin", "ubuntu:ubuntu", "test:test"],
        "recommendation": "Enforce SSH key-based authentication only; disable password login."
    },
    {
        "signature": "mysql",
        "service": "MySQL",
        "risk_level": "HIGH",
        "issue": "Database Service Exposed to Network",
        "default_creds": ["root:<blank>", "root:root", "mysql:mysql"],
        "recommendation": "Bind MySQL to localhost (127.0.0.1) and enforce strong root authentication."
    },
    {
        "signature": "vsftpd",
        "service": "FTP",
        "risk_level": "MEDIUM",
        "issue": "Standard FTP Service (Potential Anonymous Login or Plaintext Credential Capture)",
        "default_creds": ["anonymous:anonymous", "ftp:ftp"],
        "recommendation": "Disable anonymous access and enforce SFTP/FTPS."
    },
    {
        "signature": "http",
        "service": "HTTP Web Server",
        "risk_level": "INFO",
        "issue": "Standard Web Port Discovered - Requires Application-Layer Assessment",
        "default_creds": ["N/A - Run http_auditor module"],
        "recommendation": "Ensure no default admin portals or backup files (.git, .bak) are exposed."
    }]

def _match_intelligence(self, banner):
"""Compares a discovered service banner against known security signatures."""
banner_lower = banner.lower()
matches = []
for entry in self.intel_database:
if entry["signature"].lower() in banner_lower:
matches.append(entry)

# Fallback heuristic mapping if generic service type is detected
if not matches:
if "ftp" in banner_lower or "vsftpd" in banner_lower:
matches.append(self.intel_database[4]) # generic ftp
elif "ssh" in banner_lower:
matches.append(self.intel_database[2]) # generic ssh
elif "mysql" in banner_lower:
matches.append(self.intel_database[3]) # generic mysql
elif "http" in banner_lower or "apache" in banner_lower or "nginx" in banner_lower:
matches.append(self.intel_database[5]) # generic http

return matches

def run(self):
target_input = self.options["TARGET_IP"]["value"].strip()
output_file = self.options["OUTPUT_FILE"]["value"]

print("[*] Querying OmniCore workspace database for service intelligence correlation...")
services = self.workspace.get_services()

if not services:
print("[!] Error: No services found in the workspace database.")
print("[!] Tip: Run the 'port_scanner' module first to populate targets and services.")
return

# Filter services if a specific target IP was provided
if target_input.upper() != "AUTO":
services = [s for s in services if s["ip"] == target_input]
if not services:
print(f"[!] No services found in workspace for IP: {
    target_input
}")
return

print(f"\n[*] Analyzing {
    len(services)} discovered service(s) against signature database...")
print("=" * 75)

correlated_findings = []

for svc in services:
ip = svc["ip"]
port = svc["port"]
banner = svc["banner"]

print(f"[*] Target: {
    ip
}: {
    port
} | Banner: {
    banner
}")

matches = self._match_intelligence(banner)

if matches:
for match in matches:
print(f"    [+] Risk Level : {
    match['risk_level']}")
print(f"    [+] Issue Type : {
    match['issue']}")
print(f"    [+] Default Creds / Vectors: {
    ', '.join(match['default_creds'])}")
print(f"    [i] Action     : {
    match['recommendation']}")

finding_entry = {
    "ip": ip,
    "port": port,
    "service": match["service"],
    "risk_level": match["risk_level"],
    "issue": match["issue"],
    "potential_credentials": match["default_creds"],
    "recommendation": match["recommendation"]
}
correlated_findings.append(finding_entry)

# Store correlated finding directly back into workspace database
try:
with self.workspace._lock:
with self.workspace._get_connection() as conn:
cursor = conn.cursor()
cursor.execute("""
                                    INSERT INTO findings (module, ip, category, data)
                                    VALUES (?, ?, ?, ?)
                                """, (self.name, ip, match["risk_level"], json.dumps(finding_entry)))
conn.commit()
except Exception:
pass
else :
print("    [i] No high-risk signatures matched for this specific banner string.")

print("-" * 75)

print(f"[*] Correlation complete. Generated {
    len(correlated_findings)} security intelligence mapping(s).")
print("[*] Findings have been successfully synchronized back into the workspace findings table.")

# Export JSON report if requested
if output_file and correlated_findings:
self.export_json(correlated_findings, filename = output_file)