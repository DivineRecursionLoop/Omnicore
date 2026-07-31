# OmniCore Framework

> A modular, lightweight automation and reconnaissance framework built in Python.

---

## Overview

**OmniCore** is a modular, scriptable assessment framework designed for reliability, concurrency safety, and extensibility. Moving away from monolithic scripts, OmniCore provides a centralized command shell (`omnicore.py`), a thread-safe SQLite workspace backend (`workspace.py`), and a strict plugin architecture (`base_module.py`) to manage and correlate intelligence across multiple network protocols.

---

## Core Architecture

OmniCore enforces strict architectural separation to ensure stability and seamless component management:

* **Centralized Shell (`omnicore.py`)**: Built on Python's native `cmd` module, providing an interactive command-line interface with native playbook scripting support.


* **Thread-Safe Workspace (`workspace.py`)**: Manages a centralized SQLite database (housed safely in `~/.omnicore/omnicore_workspace.db`) with built-in thread locking to prevent race conditions during concurrent module execution.


* **Immutable API Contract (`base_module.py`)**: Serves as the base class blueprint for all plug-and-play modules, standardizing option parsing, workspace data queries, and JSON report generation.



---

## Framework File Structure

```text
omnicore/
│
├── omnicore.py            # Main command shell and playbook runner
├── base_module.py         # Standard plugin blueprint and workspace binder
├── workspace.py           # Thread-safe SQLite workspace manager
├── workflow.txt           # Example automated pipeline script
│
└── modules/               # Modular plugin directory
    ├── __init__.py        # Python package initializer (leave blank)
    ├── port_scanner.py               # Maps target ports and logs services[cite: 8]
    ├── http_auditor.py               # Audits web endpoints for security headers[cite: 7]
    ├── credential_reuse_mapper.py    # Matches banners against risk signatures[cite: 6]
    ├── privilege_escalation_pathfinder.py # Models host topologies into attack chains[cite: 9]
    └── attack_surface_drift_detector.py   # Computes delta drift against historical baselines[cite: 5]

```

---

## Installation & Setup

1. **Clone or download the repository** into your local environment:

```bash
git clone https://github.com/automated/omnicore.git
cd omnicore

```

2. **Ensure dependencies are met**:
The framework features an automated dependency bootstrap (`colorama`, `requests`) on its first run, but you can also install thcoloramaally:



```bash
pip install colorama requests

```

3. **Launch the Framework**:

```bash
python3 omnicore.py

```

---

## Interactive Usage & Commands

Once inside the `omnicore >` prompt, use the following commands to navigate and execute modules:

| Command | Description | Example |
| --- | --- | --- |
| `list` | List all available modules currently loaded in `modules/`<br> | `list` |
| `use <module>` | Select a specific module script to configure

 | `use port_scanner` |
| `show options` | Display configurable variables for the active module | `show options` |
| `set <opt> <val>` | Set a configuration parameter for the active module

 | `set TARGET 127.0.0.1` |
| `run` | Execute the selected module

 | `run` |
| `workspace status` | Display summary counts of targets, services, and findings

 | `workspace status` |
| `workspace services` | Print all discovered services currently tracked in the database

 | `workspace services` |
| `playbook <file>` | Execute an automated text sequence of commands line-by-line

 | `playbook workflow.txt` |
| `back` | Deselect the active module and return to the main shell

 | `back` |
| `exit` | Shutdown the framework safely

 | `exit` |

---

## Playbook Automation

OmniCore supports native resource scripts (playbooks) to chain multi-stage workflows automatically.

Create a text file named `workflow.txt`:

```text
# Automated OmniCore Pipeline
use port_scanner
set TARGET 127.0.0.1
set PORTS 22,80,443,3306
run

use http_auditor
set TARGET AUTO
run

use privilege_escalation_pathfinder
set TARGET_IP AUTO
run

workspace status

```

Then execute the entire pipeline inside the shell with a single command:

```bash
omnicore > playbook workflow.txt

```

---

## Writing Custom Modules

Adding a new capability to OmniCore is straightforward. Create a new `.py` file inside the `modules/` directory inheriting from `BaseModule`:

```python
from base_module import BaseModule

class ModuleDefinition(BaseModule):
    name = "example_module"
    description = "Performs custom research task."

    def __init__(self):
        super().__init__()
        self.options = {
            "TARGET": {
                "value": "127.0.0.1",
                "required": True,
                "description": "Target IP or hostname"
            }
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        print(f"[*] Executing custom module against {target}...")
        
        # Interact with the shared SQLite workspace safely
        services = self.workspace.get_services()
        print(f"[*] Found {len(services)} services in shared workspace database.")

```

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
