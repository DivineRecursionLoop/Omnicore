import socket
import ssl
from urllib.parse import urlparse
from base_module import BaseModule

class ModuleDefinition(BaseModule):
name = "http_auditor"
description = "Automatically audits HTTP headers and security configurations of web ports found in the workspace."

def __init__(self):
super().__init__()
self.options = {
    "TARGET": {
        "value": "AUTO",
        "required": True,
        "description": "Use 'AUTO' to target discovered web ports from workspace, or supply a specific IP/URL"
    },
    "OUTPUT_FILE": {
        "value": "http_audit_report.json",
        "required": False,
        "description": "Filename to export JSON results (leave blank to skip)"
    }
}

def _audit_url(self, url):
"""Performs a lightweight socket-based HTTP request to analyze security headers safely."""
parsed = urlparse(url)
host = parsed.hostname
port = parsed.port or (443 if parsed.scheme == "https" else 80)
path = parsed.path if parsed.path else "/"

headers_found = {}
server_banner = "Unknown"

try:
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
s.settimeout(3.0)
s.connect((host, port))

# Wrap with TLS if HTTPS
if parsed.scheme == "https":
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
try:
with context.wrap_socket(s, server_hostname = host) as ssock:
request = f"HEAD {
    path
} HTTP/1.1\r\nHost: {
    host
}\r\nConnection: close\r\n\r\n"
ssock.sendall(request.encode())
response = ssock.recv(4096).decode("utf-8", errors = "ignore")
except Exception:
return None, None, {
    "error": "TLS handshake failed"
} else :
request = f"HEAD {
    path
} HTTP/1.1\r\nHost: {
    host
}\r\nConnection: close\r\n\r\n"
s.sendall(request.encode())
response = s.recv(4096).decode("utf-8", errors = "ignore")

# Parse response headers
lines = response.split("\r\n")
status_line = lines[0] if lines else "HTTP/1.1 000 Unknown"

for line in lines[1:]:
if ":" in line:
key, val = line.split(":", 1)
headers_found[key.strip().lower()] = val.strip()

server_banner = headers_found.get("server", "Not Disclosed")
return status_line, server_banner, headers_found

except Exception as e:
return None, None, {
    "error": str(e)}

def run(self):
target_input = self.options["TARGET"]["value"].strip()
output_file = self.options["OUTPUT_FILE"]["value"]

targets_to_audit = []

# --- SMART WORKSPACE AUTO-DISCOVERY LOGIC ---
if target_input.upper() == "AUTO":
print("[*] Querying OmniCore workspace database for active services...")
all_services = self.workspace.get_services()

# Common web ports filter (Fixed unique port list)
web_ports = [80, 443, 8080, 8443, 8000, 5000]
for svc in all_services:
if svc["port"] in web_ports or "http" in svc["banner"].lower():
scheme = "https" if svc["port"] in [443, 8443, 4433] else "http"
targets_to_audit.append(f" {
    scheme
}:// {
    svc['ip']}: {
    svc['port']}")

if not targets_to_audit:
print("[!] No web services found automatically in the workspace database.")
print("[!] Tip: Run the 'port_scanner' module first, or specify a manual TARGET (e.g., set TARGET http://127.0.0.1)")
return
else :
# Handle manual single target input
if not target_input.startswith("http://") and not target_input.startswith("https://"):
targets_to_audit.append(f"http:// {
    target_input
}")
else :
targets_to_audit.append(target_input)

print(f"\n[*] Starting HTTP Security Header Audit on {
    len(targets_to_audit)} target(s)...")
print("-" * 65)

findings = []
for url in targets_to_audit:
print(f"[*] Auditing: {
    url
}")
status, server, headers = self._audit_url(url)

if not status:
print(f"    [!] Failed to connect or retrieve response: {
    headers.get('error', 'Unknown error')}")
continue

print(f"    [+] Status: {
    status
} | Server: {
    server
}")

# Check for missing critical security headers
missing_headers = []
critical_headers = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options"
]

for ch in critical_headers:
if ch not in headers:
missing_headers.append(ch)
else :
print(f"    [i] Found header: {
    ch
} = {
    headers[ch]}")

if missing_headers:
print(f"    [!] Missing Security Headers: {
    ', '.join(missing_headers)}")

# Record finding payload
finding_data = {
    "url": url,
    "status_line": status,
    "server": server,
    "missing_security_headers": missing_headers,
    "all_headers": headers
}
findings.append(finding_data)

# Sync target domain back to workspace targets table safely
parsed_url = urlparse(url)
if parsed_url.hostname:
self.workspace.add_target(parsed_url.hostname)

print("-" * 65)

# Export JSON report if requested
if output_file and findings:
self.export_json(findings, filename = output_file)
print(f"[*] Audit complete. Processed {
    len(findings)} target(s).")