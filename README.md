# OmniCore Framework

**OmniCore is a lightweight, modular Python framework designed to centralize multi-source network reconnaissance data into a thread-safe SQLite workspace and translate it into actionable, interactive visualizations.**

---

## Core Concept

OmniCore solves the fragmentation problem inherent in traditional reconnaissance workflows by organizing data around three key principles:

**Centralized Persistence (workspace.py)** — All module outputs, target states, and reconnaissance data flow through a strict SQLite schema. This eliminates scattered text logs and maintains a persistent local session that survives across tool invocations.

**Relationship & Topology Visualization (graph_exporter.py)** — Raw structured data stored in the workspace transforms into interactive node graphs. You can visually map network relationships, attack paths, and surface changes instead of parsing endless text output.

**Modular Recon Modules (modules/)** — Standalone scripts handle multi-threaded port scanning, banner correlation, service auditing, privilege escalation pathfinding, and historical drift detection. Each module inherits from a standardized base class and reports output as JSON into the workspace.

**Automated Workflows (workflow.txt)** — Support for line-by-line script playbooks via the interactive shell enables you to automate multi-step collection tasks without manual intervention.

---

## Framework Architecture

```
omnicore/
├── omnicore.py              # Interactive CLI shell & framework core
├── base_module.py           # Standardized abstract class for module options & JSON reporting
├── workspace.py             # Thread-safe SQLite database backend & schema manager
├── workflow.txt             # Automated command playbook
└── modules/
    ├── attack_surface_drift_detector.py  # Isolates new/closed ports and risk shifts
    ├── bundle_export.py                  # Packages workspace data for transport
    ├── credential_reuse_mapper.py        # Cross-references service banners against risk signatures
    ├── graph_exporter.py                 # Exports workspace data into visual node maps
    ├── http_auditor.py                   # Audits web service endpoints
    ├── mock_generator.py                 # Generates test data for workspace validation
    ├── port_scanner.py                   # Multi-threaded TCP port scanner with TLS/HTTP banner grabbing
    ├── privilege_escalation_pathfinder.py# Models host topologies into local pivot paths
    └── snapshot_diff.py                  # Computes quantitative risk deltas against baselines
```

---

## Usage & Command Reference

### Launching the Framework

Start the interactive CLI shell:

```bash
python3 omnicore.py
```

### Interactive Shell Commands

| Command | Action |
|---------|--------|
| `list` | Display all available module scripts currently loaded |
| `use <module>` | Select a specific module script to work with |
| `show options` | View configuration options for the active module |
| `set <opt> <val>` | Configure a parameter for the active module |
| `run` | Execute the currently selected module script |
| `workspace status` | View database metrics for tracked targets, services, and findings |
| `workspace services` | List all discovered services recorded in the database |
| `playbook <file>` | Execute an automated, line-by-line workflow script file |
| `back` | Deselect the current module and return to the root shell |
| `exit` | Safely shutdown the framework and database connection |
