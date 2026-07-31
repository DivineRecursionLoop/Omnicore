# OmniCore Framework

OmniCore is a lightweight, modular Python framework for offline network reconnaissance and data structuring. It is not an exploitation framework; rather, it acts as a localized database wrapper to bring order, persistence, and visual clarity to standard reconnaissance tasks.

Because it operates entirely without cloud dependencies, it is highly suited for air-gapped environments or integration into custom physical hardware loadouts.

---

## What It Actually Does

* **Centralized Data Structuring**: The core of the project. All module outputs are routed through a thread-safe SQLite database with a strict schema (`workspace.py`). This prevents messy text outputs and keeps session data permanently organized.


* **Offline Visualization**: Translates the SQLite workspace into an interactive HTML node graph to easily visualize network topology, choke points, and surface changes offline (`graph_exporter.py`).


* **Target Mapping**: Executes multi-threaded TCP port scanning with basic HTTP/TLS banner grabbing to populate the database (`port_scanner.py`).


* **Drift Tracking**: Compares the current workspace state against historical baseline snapshots to track which ports have opened or closed over time (`snapshot_diff.py`).


* **Custom Ingestion Ready**: The offline SQLite backend makes it simple to feed external data into the workspace. For example, it can easily be modified to ingest and correlate passively captured network handshakes logged directly to a local SD card module.

---

## Instructions & Usage

### 1. Launch the Framework

Ensure the required dependencies (`colorama`, `requests`) are installed locally, then launch the interactive shell:

```bash
python3 omnicore.py

```

### 2. Command Reference

| Command | Action |
| --- | --- |
| `list` | Display all available modules

 |
| `use <module>` | Select a specific module for execution

 |
| `show options` | View configurable parameters for the active module

 |
| `set <opt> <val>` | Configure a parameter (e.g., `set TARGET 192.168.1.50`)

 |
| `run` | Execute the currently selected module

 |
| `workspace status` | View database metrics for tracked targets and services

 |
| `workspace services` | List all discovered services currently recorded in the SQLite database

 |
| `playbook <file>` | Execute an automated, line-by-line workflow script

 |
| `back` | Deselect the module and return to the main root shell

 |
| `exit` | Shutdown the framework and database connection safely

 |

* **Hardware Integration Ready**: The localized, offline SQLite structure makes it an ideal engine for custom physical kits—perfect for ingesting external offline data, such as parsing passively captured network handshakes logged locally to an SD card.
* **Playbook Automation**: Supports native, line-by-line workflow execution via text-based scripts, allowing operators to chain complex multi-module assessments automatically without manual shell interaction.



---

## Operational Instructions

### 1. Launch the Framework

OmniCore requires `colorama` and `requests`. Ensure these are installed in your local environment, then launch the interactive shell:

```bash
python3 omnicore.py

```

### 2. Command Reference

| Command | Action |
| --- | --- |
| `list` | Display all loaded tactical modules

 |
| `use <module>` | Select a specific module for execution

 |
| `show options` | View configurable parameters for the active module

 |
| `set <opt> <val>` | Configure a target or parameter (e.g., `set TARGET 192.168.1.5`)

 |
| `run` | Execute the currently selected module

 |
| `workspace status` | View database metrics (tracked targets, services, findings)

 |
| `workspace services` | List all discovered services currently recorded in the SQLite database

 |
| `playbook <file>` | Execute an automated, line-by-line workflow script

 |
| `back` | Deselect the module and return to the main root shell

 |
| `exit` | Safely spin down the framework and terminate the session

 |
