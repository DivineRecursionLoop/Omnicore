OmniCore Framework
OmniCore is a lightweight, modular Python framework designed to bring order to multi-source network reconnaissance. Instead of leaving you with fragmented output files and disconnected scripts, OmniCore centralizes your data into a thread-safe local SQLite workspace and translates it into actionable, interactive visualizations.

The Core Concept
Centralized Persistence (workspace.py): Routes all module outputs, target states, and recon data through a strict SQLite schema, eliminating messy text logs and maintaining a persistent local session.

Relationship & Topology Visualization (graph_exporter.py): Transforms the raw structured data stored in your workspace into interactive node graphs, allowing you to visually map network relationships, attack paths, and surface changes rather than parsing endless text.

Modular Recon Modules (modules/): Houses standalone scripts for multi-threaded port scanning, banner correlation, service auditing, privilege escalation pathfinding, and historical drift detection.

Automated Workflows (workflow.txt): Supports line-by-line script playbooks via the interactive shell to automate multi-step collection tasks.

Framework Architecture & Structure
Plaintext
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
Usage & Command Reference
1. Launching the Framework
Start the interactive CLI shell:

Bash
python3 omnicore.py
2. Interactive Shell Commands
Command	Action
list	Display all available module scripts currently loaded
use <module>	Select a specific module script to work with
show options	View configuration options for the active module
set <opt> <val>	Configure a parameter for the active module
run	Execute the currently selected module script
workspace status	View database metrics for tracked targets, services, and findings
workspace services	List all discovered services recorded in the database
playbook <file>	Execute an automated, line-by-line workflow script file
back	Deselect the current module and return to the root shell
exit	Safely shutdown the framework and database connection
