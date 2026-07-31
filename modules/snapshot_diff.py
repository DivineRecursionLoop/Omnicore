from base_module import BaseModule

class ModuleDefinition(BaseModule):
name = "snapshot_diff"
description = "Computes a mathematical delta and risk score shift between the current workspace state and historical baseline snapshots."

def run(self):
print("[*] Computing time-travel delta against historical baseline via WorkspaceManager API...")

try:
current_services = {
f" {
    s['ip']}: {
    s['port']}": s["banner"] for s in self.workspace.get_services()}
baseline_services = {
f" {
    s['ip']}: {
    s['port']}" for s in self.workspace.get_snapshots()}

if not current_services:
print("[!] Error: No current services found in workspace to analyze.")
return

current_keys = set(current_services.keys())

new_exposures = current_keys - baseline_services
remediated_exposures = baseline_services - current_keys

high_risk_ports = {
    22, 80, 445, 3389, 3306, 6379, 5432
}

risk_score_change = 0
for key in new_exposures:
port = int(key.split(":")[1])
risk_score_change += 15 if port in high_risk_ports else 5

for key in remediated_exposures:
port = int(key.split(":")[1])
risk_score_change -= 10 if port in high_risk_ports else 3

print("\n" + "="*50)
print(" OMNICORE // ATTACK SURFACE DELTA REPORT")
print("="*50)
print(f"[*] Total Active Endpoints/Ports Scanned: {
    len(current_services)}")
print(f"[*] Baseline Snapshot Count: {
    len(baseline_services)}")
print(f"[*] Calculated Risk Score Shift: {
    risk_score_change:+d
}%")
print("-" * 50)

if new_exposures:
print("[+] NEW EXPOSURES DETECTED:")
for key in sorted(new_exposures):
banner = current_services[key]
print(f"    -> Host {
    key
} ( {
    banner
})")
else :
print("[+] New Exposures: None")

if remediated_exposures:
print("[-] REMEDIATED EXPOSURES:")
for key in sorted(remediated_exposures):
print(f"    -> Host {
    key
} no longer exposed")
else :
print("[-] Remediated Exposures: None")
print("="*50 + "\n")

except Exception as e:
print(f"[!] Error calculating snapshot delta: {
    e
}")