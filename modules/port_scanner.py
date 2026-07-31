import socket
import concurrent.futures
import time
import ssl
from base_module import BaseModule

class ModuleDefinition(BaseModule):
name = "port_scanner"
description = "Advanced multi-threaded TCP port scanner with banner grabbing and workspace sync."

def __init__(self):
super().__init__()
self.options = {
    "TARGET": {
        "value": "127.0.0.1",
        "required": True,
        "description": "Target IP address or hostname to scan"
    },
    "PORTS": {
        "value": "21,22,23,25,80,443,445,3306,8080",
        "required": True,
        "description": "Ports to scan (comma-separated or range like 1-1024)"
    },
    "THREADS": {
        "value": "50",
        "required": True,
        "description": "Number of concurrent worker threads"
    },
    "GRAB_BANNER": {
        "value": "true",
        "required": True,
        "description": "Attempt to grab service banners on open ports (true/false)"
    },
    "OUTPUT_FILE": {
        "value": "scan_report.json",
        "required": False,
        "description": "Filename to export JSON results (leave blank to skip)"
    }
}

def _grab_banner(self, s, port, target_ip):
"""Attempts to pull identifying headers or service data safely."""
try:
s.settimeout(2.0)

# Handle HTTPS / TLS ports separately
if port in [443, 8443, 4433]:
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
try:
with context.wrap_socket(s, server_hostname = target_ip) as ssock:
ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
banner = ssock.recv(1024)
if banner:
return banner.decode("utf-8", errors = "ignore").strip().split("\n")[0]
except Exception:
return "HTTPS / TLS Service (No Banner)"

# Handle standard plaintext TCP/HTTP services
else :
if port in [80, 8080, 8000, 5000]:
time.sleep(0.05)
s.sendall(b"HEAD / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")

banner = s.recv(1024)
if banner:
decoded = banner.decode("utf-8", errors = "ignore").strip().split("\n")[0]
return decoded if decoded else "Open (Empty Response)"

except socket.timeout:
return "Open (Timeout waiting for banner)"
except ConnectionResetError:
return "Open (Connection reset by peer)"
except Exception:
pass

return "Unknown / No Banner"

def _scan_port(self, target_ip, port, grab_banners):
try:
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
s.settimeout(1.5)
result = s.connect_ex((target_ip, port))
if result == 0:
banner = "N/A"
if grab_banners:
banner = self._grab_banner(s, port, target_ip)
return port, banner
except Exception:
pass
return None, None

def _parse_ports(self, port_str):
ports = []
parts = port_str.split(",")
for part in parts:
part = part.strip()
if "-" in part:
try:
start, end = map(int, part.split("-"))
ports.extend(range(start, end + 1))
except ValueError:
continue
else :
try:
ports.append(int(part))
except ValueError:
continue
return sorted(list(set(ports)))

def run(self):
target = self.options["TARGET"]["value"]
port_input = self.options["PORTS"]["value"]
grab_banners = self.options["GRAB_BANNER"]["value"].lower() == "true"
output_file = self.options["OUTPUT_FILE"]["value"]

try:
max_threads = int(self.options["THREADS"]["value"])
except ValueError:
max_threads = 50

try:
target_ip = socket.gethostbyname(target)
except socket.gaierror:
print(f"[!] Error: Could not resolve hostname ' {
    target
}'")
return

ports = self._parse_ports(port_input)
if not ports:
print("[!] Error: No valid ports specified.")
return

print(f"\n[*] Starting multi-threaded port scan on {
    target
} ( {
    target_ip
})")
print(f"[*] Total ports to scan: {
    len(ports)} | Threads: {
    max_threads
} | Banner Grabbing: {
    grab_banners
}")
print("-" * 65)

start_time = time.time()
findings = []

with concurrent.futures.ThreadPoolExecutor(max_workers = max_threads) as executor:
future_to_port = {
    executor.submit(self._scan_port, target_ip, port, grab_banners): port
    for port in ports
}

for future in concurrent.futures.as_completed(future_to_port):
try:
port, banner = future.result()
if port:
findings.append({
    "port": port, "status": "OPEN", "service": banner
})
print(f"[+] Port {
    port:<5
} OPEN  | Service: {
    banner
}")

# --- SYNC DIRECTLY TO SHARED WORKSPACE DB ---
self.workspace.add_service(ip = target_ip, port = port, state = "OPEN", banner = banner)

except Exception:
pass

duration = time.time() - start_time
print("-" * 65)
print(f"[*] Scan completed in {
    duration:.2f
} seconds.")
print(f"[*] Found {
    len(findings)} open port(s) and logged them to the workspace database.")

# Export JSON report if requested
if output_file:
report_payload = {
    "target": {
        "hostname": target, "ip_address": target_ip
    },
    "scan_parameters": {
        "total_ports_scanned": len(ports), "threads_used": max_threads
    },
    "statistics": {
        "duration_seconds": round(duration, 2), "open_ports_count": len(findings)},
    "open_ports": sorted(findings, key = lambda k: k["port"])
}
self.export_json(report_payload, filename = output_file)