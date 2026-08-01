#!/usr/bin/env python3
import sys
import importlib
import os
import cmd
import logging
import traceback

logging.basicConfig(
    filename="omnicore_framework.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

from colorama import init, Fore, Style
init(autoreset=True)

class OmniCoreShell(cmd.Cmd):
    intro = f"""{Fore.GREEN}
____                  _  ____
/ __ \\                 | |/ ____|
| |  | |_ __ ___  _ __  | | |     ___  _ __ ___
| |  | | '_ ` _ \\| '_ \\ | | |    / _ \\| '__/ _ \\
| |__| | | | | | | | | || | |___| (_) | | |  __/
\\____/|_| |_| |_|_| |_||_|\\_____\\___/|_|  \\___|

[Modular Security & Research Framework]
Type 'help' to view core commands, 'list' to see loaded modules, or 'playbook <file>'.
{Style.RESET_ALL}"""
    
    prompt = f"{Fore.BLUE}omnicore > {Style.RESET_ALL}"

    def __init__(self):
        super().__init__()
        self.modules = {}
        self.active_module = None
        self.load_modules()

    def load_modules(self):
        base_dir = os.path.abspath(os.path.dirname(__file__))
        mod_dir = os.path.join(base_dir, "modules")

        if not os.path.exists(mod_dir):
            os.makedirs(mod_dir, exist_ok=True)
            with open(os.path.join(mod_dir, "__init__.py"), "w") as f:
                f.write("")

        if base_dir not in sys.path:
            sys.path.insert(0, base_dir)

        for file in os.listdir(mod_dir):
            if file.endswith(".py") and file != "__init__.py":
                mod_name = file[:-3]
                try:
                    module = importlib.import_module(f"modules.{mod_name}")
                    importlib.reload(module)
                    if hasattr(module, "ModuleDefinition"):
                        if not issubclass(module.ModuleDefinition, BaseModule):
                            raise TypeError(f"{mod_name}.ModuleDefinition must extend BaseModule")
                        instance = module.ModuleDefinition()
                        self.modules[instance.name] = instance
                        logging.info(f"Loaded module script: {instance.name}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error loading script '{mod_name}': {e}{Style.RESET_ALL}")
                    logging.error(f"Failed to load {mod_name}: {e}\n{traceback.format_exc()}")

    def do_list(self, arg):
        """List all available module scripts currently loaded in the framework."""
        print(f"\n{Fore.YELLOW}[Loaded Framework Modules]{Style.RESET_ALL}")
        if not self.modules:
            print("  No scripts found in 'modules/' directory.")
            return
        for name, mod in self.modules.items():
            print(f"{Fore.GREEN}{name:<32}{Style.RESET_ALL} - {mod.description}")
        print("")

    def do_use(self, mod_name):
        """Select a module script to work with: use <module_name>"""
        mod_name = mod_name.strip()
        if mod_name in self.modules:
            self.active_module = self.modules[mod_name]
            self.prompt = f"{Fore.BLUE}omnicore ({Fore.RED}{mod_name}{Fore.BLUE}) > {Style.RESET_ALL}"
            print(f"[*] Active module set to: {Fore.GREEN}{mod_name}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Module '{mod_name}' not found. Type 'list' to see options.{Style.RESET_ALL}")

    def do_back(self, arg):
        """Deselect the current module script and return to the main framework shell."""
        self.active_module = None
        self.prompt = f"{Fore.BLUE}omnicore > {Style.RESET_ALL}"
        print("[*] Returned to main framework context.")

    def do_set(self, arg):
        """Configure an option for the active module: set <option_name> <value>"""
        if not self.active_module:
            print(f"{Fore.RED}[!] No active module selected. Use 'use <module_name>' first.{Style.RESET_ALL}")
            return

        parts = arg.split(maxsplit=1)
        if len(parts) < 2:
            print(f"{Fore.RED}[!] Usage: set <option_name> <value>{Style.RESET_ALL}")
            return

        key, value = parts[0].upper(), parts[1]
        self.active_module.set_option(key, value)
        print(f"{Fore.CYAN}{key}{Style.RESET_ALL} => {value}")

    def do_show(self, arg):
        """Show configuration options for the active module: show options"""
        arg = arg.strip().lower()
        if arg == "options":
            if not self.active_module:
                print(f"{Fore.RED}[!] No active module selected.{Style.RESET_ALL}")
                return
            print(f"\n{Fore.YELLOW}[Configuration Options for {self.active_module.name}]{Style.RESET_ALL}")
            print(f"{'Option':<15} {'Value':<20} {'Required':<10} {'Description'}")
            print("-" * 65)
            for opt, details in self.active_module.options.items():
                val = details.get("value", "")
                req = str(details.get("required", False))
                desc = details.get("description", "")
                print(f"{Fore.CYAN}{opt:<15}{Style.RESET_ALL} {str(val):<20} {req:<10} {desc}")
            print("")
        else:
            print(f"{Fore.RED}[!] Unknown argument. Try: show options{Style.RESET_ALL}")

    def do_workspace(self, arg):
        """Manage shared session workspace: workspace status | workspace services"""
        arg = arg.strip().lower()
        from workspace import WorkspaceManager
        ws = WorkspaceManager()

        if arg == "status" or not arg:
            summary = ws.get_summary()
            print(f"\n{Fore.YELLOW}[OmniCore Workspace Summary]{Style.RESET_ALL}")
            print(f"  Tracked Targets : {summary['targets']}")
            print(f"  Discovered Ports: {summary['services']}")
            print(f"  Saved Findings  : {summary['findings']}\n")

        elif arg == "services":
            services = ws.get_services()
            print(f"\n{Fore.YELLOW}[Discovered Services in Workspace]{Style.RESET_ALL}")
            print(f"{'IP Address':<18} {'Port':<8} {'State':<8} {'Banner'}")
            print("-" * 55)
            for s in services:
                print(f"{Fore.CYAN}{s['ip']:<18}{Style.RESET_ALL} {s['port']:<8} {s['state']:<8} {s['banner']}")
            print("")
        else:
            print(f"{Fore.RED}[!] Unknown workspace command. Try: workspace status or workspace services{Style.RESET_ALL}")

    def do_run(self, arg):
        """Execute the currently selected module script."""
        if not self.active_module:
            print(f"{Fore.RED}[!] No module selected. Use 'use <module_name>' first.{Style.RESET_ALL}")
            return

        print(f"[*] Executing module: {self.active_module.name}...")
        try:
            self.active_module.run()
        except Exception as e:
            print(f"{Fore.RED}[!] Module crashed during execution: {e}{Style.RESET_ALL}")
            logging.error(f"Module {self.active_module.name} crashed: {e}\n{traceback.format_exc()}")

    def do_playbook(self, arg):
        """Execute an automated workflow script file line-by-line: playbook <filename>"""
        filename = arg.strip()
        if not filename:
            print(f"{Fore.RED}[!] Usage: playbook <filename.txt>{Style.RESET_ALL}")
            return

        if not os.path.exists(filename):
            print(f"{Fore.RED}[!] Playbook file '{filename}' not found in current directory.{Style.RESET_ALL}")
            return

        print(f"[*] Loading and executing playbook sequence: {Fore.GREEN}{filename}{Style.RESET_ALL}")
        print("=" * 65)

        try:
            with open(filename, "r") as f:
                for line in f:
                    cmd_line = line.strip()
                    if not cmd_line or cmd_line.startswith("#"):
                        continue

                    print(f"\n{Fore.YELLOW}omnicore > {cmd_line}{Style.RESET_ALL}")
                    self.onecmd(cmd_line)

            print("\n" + "=" * 65)
            print("[*] Playbook execution completed successfully.")
        except Exception as e:
            print(f"{Fore.RED}[!] Error executing playbook: {e}{Style.RESET_ALL}")

    def do_exit(self, arg):
        """Exit and shutdown the OmniCore framework safely."""
        print("[*] Shutting down OmniCore framework. Goodbye!")
        return True


# Import after logging setup
from base_module import BaseModule


if __name__ == "__main__":
    try:
        OmniCoreShell().cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Exiting safely.")
        sys.exit(0)
