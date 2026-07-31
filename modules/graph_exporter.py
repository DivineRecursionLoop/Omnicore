import json
import os
from base_module import BaseModule

class ModuleDefinition(BaseModule):
name = "graph_exporter"
description = "Generates an air-gapped, interactive HTML decision-engine visualizer combining attack surface drift and pivot choke points."

def __init__(self):
super().__init__()
self.options = {
    "OUTPUT_FILE": {
        "value": "omnicore_visual_report.html",
        "required": False,
        "description": "Filename for the generated interactive HTML decision graph"
    }
}

def _get_snapshot_map(self):
"""Retrieves latest snapshot state via public WorkspaceManager API to compute drift."""
snapshot_map = {}
try:
snapshots = self.workspace.get_snapshots()
for s in snapshots:
snapshot_map[f" {
    s['ip']}: {
    s['port']}"] = s["state"]
except Exception:
pass
return snapshot_map

def run(self):
output_filename = self.options["OUTPUT_FILE"]["value"]
print("[*] Compiling workspace intelligence for graph visualization...")

services = self.workspace.get_services()
if not services:
print("[!] Error: No services found in workspace database to visualize.")
print("[!] Tip: Run a port scan or playbook first.")
return

snapshot_map = self._get_snapshot_map()

hosts = {}
for s in services:
ip = s["ip"]
if ip not in hosts:
hosts[ip] = []
hosts[ip].append(s)

nodes = []
edges = []

nodes.append({
    "id": "OMNICORE_HUB",
    "label": "OmniCore Workspace\n[Central Database]",
    "shape": "hexagon",
    "color": {
        "background": "#1e1e2f", "border": "#00ffcc", "highlight": {
            "background": "#2d2d44", "border": "#00ffcc"
        }
    },
    "font": {
        "color": "#00ffcc", "face": "Courier New", "bold": True
    },
    "size": 30
})

for ip, host_services in hosts.items():
open_ports = [s["port"] for s in host_services if s["state"].upper() == "OPEN"]

host_drift_status = "STABLE"
for s in host_services:
key = f" {
    ip
}: {
    s['port']}"
if key not in snapshot_map:
host_drift_status = "NEW_EXPOSURE"
break

node_color = "#2b2b3b"
border_color = "#00ffcc"

if len(open_ports) >= 3 or 445 in open_ports or 22 in open_ports:
node_color = "#3d1414"
border_color = "#ff4444"
label_suffix = "\n[HIGH BLAST RADIUS]"
elif host_drift_status == "NEW_EXPOSURE":
node_color = "#143d2b"
border_color = "#00ff77"
label_suffix = "\n[DRIFT: NEW SURFACE]"
else :
label_suffix = "\n[STABLE]"

node_label = f"Host: {
    ip
}\nPorts: {
    open_ports
} {
    label_suffix
}"

nodes.append({
    "id": ip,
    "label": node_label,
    "shape": "box",
    "color": {
        "background": node_color, "border": border_color, "highlight": {
            "background": node_color, "border": "#ffffff"
        }
    },
    "font": {
        "color": "#e0e0e0", "face": "Courier New", "size": 14
    },
    "margin": 10
})

edges.append({
    "from": "OMNICORE_HUB",
    "to": ip,
    "color": {
        "color": "#444455", "highlight": "#00ffcc"
    },
    "width": 2,
    "dashes": True
})

if any(p in open_ports for p in [80, 443, 8080]) and 3306 in open_ports:
nodes.append({
    "id": f"CHAIN_ {
        ip
    }",
    "label": f"Compound Vector\nWeb + DB Chain",
    "shape": "ellipse",
    "color": {
        "background": "#4a154b", "border": "#e0115f"
    },
    "font": {
        "color": "#ffffff", "size": 12, "face": "Courier New"
    }
})
edges.append({
    "from": ip, "to": f"CHAIN_ {
        ip
    }", "color": {
        "color": "#e0115f"
    }, "width": 3
})

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OmniCore Decision-Engine Visualizer</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{
    background-color: #0f111a;
            color: #a9b1d6;
            font-family: 'Courier New', Courier, monospace;
            margin: 0;
            padding: 0;
            overflow: hidden;
}}
        #header {{
    background: #1a1b26;
            padding: 15px 25px;
            border-bottom: 2px solid #00ffcc;
            display: flex;
            justify-content: space-between;
            align-items: center;
}}
        h1 {{
    margin: 0;
            color: #00ffcc;
            font-size: 20px;
            letter-spacing: 1px;
}}
        #stats {{
    font-size: 14px;
            color: #bb9af7;
}}
        #network {{
    width: 100vw;
            height: calc(100vh - 65px);
}}
        #legend {{
    position: absolute;
            bottom: 20px;
            left: 20px;
            background: rgba(26, 27, 38, 0.9);
            border: 1px solid #414868;
            padding: 15px;
            border-radius: 5px;
            font-size: 12px;
            pointer-events: none;
}}
        .legend-item {{
    display: flex;
            align-items: center;
            margin-bottom: 5px;
}}
        .legend-color {{
    width: 15px;
            height: 15px;
            margin-right: 10px;
            border-radius: 3px;
}}
    </style>
</head>
<body>
    <div id="header">
        <h1>OMNICORE // DECISION-ENGINE VISUALIZER</h1>
        <div id="stats">Hosts Mapped: {
    len(hosts)} | Services Tracked: {
    len(services)}</div>
    </div>
    <div id="network"></div>

    <div id="legend">
        <div style="font-weight: bold; margin-bottom: 8px; color: #00ffcc;">TACTICAL LEGEND</div>
        <div class="legend-item"><div class="legend-color" style="background: #3d1414; border: 1px solid #ff4444;"></div>High Blast Radius / Choke Point</div>
        <div class="legend-item"><div class="legend-color" style="background: #143d2b; border: 1px solid #00ff77;"></div>New Attack Surface (Drift)</div>
        <div class="legend-item"><div class="legend-color" style="background: #4a154b; border: 1px solid #e0115f;"></div>Compound Attack Chain</div>
        <div class="legend-item"><div class="legend-color" style="background: #2b2b3b; border: 1px solid #00ffcc;"></div>Stable Baseline Node</div>
    </div>

    <script type="text/javascript">
        var nodes = new vis.DataSet( {
    json.dumps(nodes)});
        var edges = new vis.DataSet( {
    json.dumps(edges)});

        var container = document.getElementById('network');
        var data = {{
        nodes: nodes, edges: edges
    }};
        var options = {{
        nodes: {{
            borderWidth: 2, shadow: true
        }},
            edges: {{
            shadow: true, smooth: {{
                type: 'cubicBezier', roundness: 0.2
            }}
        }},
            physics: {{
            barnesHut: {{
                gravitationalConstant: -3000,
                    centralGravity: 0.4,
                    springLength: 120,
                    springConstant: 0.04
            }}
        }},
            interaction: {{
            hover: true, zoomView: true
        }}
    }};
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>
"""

reports_dir = os.path.expanduser("~/.omnicore/reports")
os.makedirs(reports_dir, exist_ok = True)
file_path = os.path.join(reports_dir, output_filename)

try:
with open(file_path, "w", encoding = "utf-8") as f:
f.write(html_content)
print(f"[+] Interactive decision graph successfully compiled and saved to:\n {
    file_path
}")
except Exception as e:
print(f"[!] Error exporting graph HTML: {
    e
}")