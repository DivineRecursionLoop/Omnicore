import json
import os
from workspace import WorkspaceManager

class BaseModule:
    name = "base_module"
    description = "Abstract blueprint for all OmniCore plugins."

    def __init__(self):
        self.options = {}
        self.workspace = WorkspaceManager()

    def set_option(self, key, value):
        """Set a module option with validation."""
        key = key.upper()
        if key in self.options:
            self.options[key]["value"] = value
        else:
            print(f"[!] Warning: Option '{key}' does not exist for module '{self.name}'.")

    def export_json(self, data, filename="report.json"):
        """Safely export findings or scan results to a JSON file."""
        try:
            if not os.path.isabs(filename):
                reports_dir = os.path.expanduser("~/.omnicore/reports")
                os.makedirs(reports_dir, exist_ok=True)
                filename = os.path.join(reports_dir, filename)

            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            print(f"[*] Report successfully exported to: {filename}")
        except Exception as e:
            print(f"[!] Error exporting JSON report: {e}")

    def run(self):
        raise NotImplementedError("Modules must implement their own run() method.")
