import json
from base_module import BaseModule

class ModuleDefinition(BaseModule):
name = "attack_surface_drift_detector"
description = "Snapshots current workspace service state and computes drift (new, closed, or modified ports) against historical baselines."

def __init__(self):
super().__init__()
self.options = {
    "ACTION": {
        "value": "CHECK",
        "required": True,
        "description": "Action to perform: 'SNAPSHOT' (save current state) or 'CHECK' (compare current vs last snapshot)"
    },
    "OUTPUT_FILE": {
        "value": "drift_report.json",
        "required": False,
        "description": "Filename to export JSON drift analysis report"
    }
}

def run(self):
action = self.options["ACTION"]["value"].strip().upper()
output_file = self.options["OUTPUT_FILE"]["value"]

if action == "SNAPSHOT":
print("[*] Taking attack surface snapshot of current workspace state...")
self.workspace.save_snapshot()
print("[+] Successfully captured baseline snapshot.")
return

elif action == "CHECK":
print("[*] Querying historical baseline snapshot and comparing current workspace state...")
baseline = self.workspace.get_snapshots()

if not baseline:
print("[!] Error: No baseline snapshot found in the workspace database.")
print("[!] Tip: Run 'set ACTION SNAPSHOT' first to establish a baseline before checking for drift.")
return

current_services = self.workspace.get_services()

baseline_map = {
f" {
    s['ip']}: {
    s['port']}": s for s in baseline
}
current_map = {
f" {
    s['ip']}: {
    s['port']}": s for s in current_services
}

baseline_keys = set(baseline_map.keys())
current_keys = set(current_map.keys())

new_ports = current_keys - baseline_keys
closed_ports = baseline_keys - current_keys
common_ports = baseline_keys.intersection(current_keys)

banner_changes = []
for key in common_ports:
old_banner = baseline_map[key]["banner"]
new_banner = current_map[key]["banner"]
if old_banner != new_banner:
banner_changes.append({
    "target": key,
    "old_banner": old_banner,
    "new_banner": new_banner
})

print("\n" + "=" * 65)
print("[*] ATTACK SURFACE DRIFT ANALYSIS REPORT")
print("=" * 65)

print(f"\n[+] Newly Opened Ports / Services Detected: {
    len(new_ports)}")
for key in sorted(new_ports):
svc = current_map[key]
print(f"    -> [NEW] {
    svc['ip']}: {
    svc['port']} ( {
    svc['state']}) | Banner: {
    svc['banner']}")

print(f"\n[-] Closed / Dropped Services Detected: {
    len(closed_ports)}")
for key in sorted(closed_ports):
svc = baseline_map[key]
print(f"    -> [CLOSED] {
    svc['ip']}: {
    svc['port']} (Was: {
    svc['banner']})")

print(f"\n[~] Service Banner / Version Modifications: {
    len(banner_changes)}")
for change in banner_changes:
print(f"    -> [MODIFIED] {
    change['target']}")
print(f"       Old: {
    change['old_banner']}")
print(f"       New: {
    change['new_banner']}")

print("\n" + "=" * 65)

drift_summary = {
    "new_ports": [current_map[k] for k in new_ports],
    "closed_ports": [baseline_map[k] for k in closed_ports],
    "banner_changes": banner_changes
}

self.workspace.add_finding(self.name, "GLOBAL", "ATTACK_SURFACE_DRIFT", json.dumps(drift_summary))

if output_file:
self.export_json(drift_summary, filename = output_file)

else :
print(f"[!] Unknown action ' {
    action
}'. Use 'SNAPSHOT' or 'CHECK'.")