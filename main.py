#!/usr/bin/env python3

import sys
from pathlib import Path


# Dynamically find the absolute path to the repository root
ROOT_DIR = Path(__file__).resolve().parent

# Ensure the root directory is prioritized in the Python path.
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Cleanly import the GUI entry point from our newly packaged src/ folder
from src import run_gui

def main():
    print("[*] Initializing NIDS Environment...")
    print(f"[*] Root Directory Locked: {ROOT_DIR}")
    print("[*] Launching Command Center GUI...")
    
    try:
        # Launch the gui
        run_gui()
        
    except KeyboardInterrupt:
        print("\n[*] Keyboard interrupt detected. Exiting NIDS...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[FATAL LAUNCH ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()