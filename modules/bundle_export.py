import os
import shutil
import datetime
from base_module import BaseModule

class ModuleDefinition(BaseModule):
name = "bundle_export"
description = "Bundles the SQLite workspace database, latest HTML visualizer report, and logs into a secure air-gapped archive."

def __init__(self):
super().__init__()
self.options = {
    "ARCHIVE_NAME": {
        "value": "omnicore_audit_bundle",
        "required": False,
        "description": "Base filename prefix for the generated zip archive"
    }
}

def run(self):
prefix = self.options["ARCHIVE_NAME"]["value"]
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bundle_name = f" {
    prefix
}_ {
    timestamp
}"

bundles_dir = os.path.expanduser("~/.omnicore/bundles")
staging_dir = os.path.expanduser(f"~/.omnicore/ {
    bundle_name
}")
os.makedirs(bundles_dir, exist_ok = True)
os.makedirs(staging_dir, exist_ok = True)

print("[*] Assembling air-gapped artifact bundle...")

try:
db_path = getattr(self.workspace, "db_path", os.path.expanduser("~/.omnicore/workspace.db"))
if os.path.exists(db_path):
shutil.copy(db_path, os.path.join(staging_dir, "workspace.db"))
print(f"    -> Attached workspace database: {
    db_path
}")

reports_dir = os.path.expanduser("~/.omnicore/reports")
if os.path.exists(reports_dir):
reports = [os.path.join(reports_dir, f) for f in os.listdir(reports_dir) if f.endswith(".html")]
if reports:
latest_report = max(reports, key = os.path.getmtime)
shutil.copy(latest_report, os.path.join(staging_dir, os.path.basename(latest_report)))
print(f"    -> Attached visual report: {
    os.path.basename(latest_report)}")

archive_path = os.path.join(bundles_dir, bundle_name)
shutil.make_archive(archive_path, 'zip', staging_dir)

shutil.rmtree(staging_dir)

final_zip = f" {
    archive_path
}.zip"
print(f"[+] Artifact bundle successfully sealed at:")
print(f" {
    final_zip
}")
print(f"[*] Ready for secure transport out of air-gapped zones.")

except Exception as e:
print(f"[!] Error creating artifact bundle: {
    e
}")