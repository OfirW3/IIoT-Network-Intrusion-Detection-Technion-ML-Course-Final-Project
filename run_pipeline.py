#!/usr/bin/env python3

import subprocess
import time
import sys
from pathlib import Path
from datetime import datetime
import os
            
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def main():
    print(f"[{now()}] Starting the End-to-End Intrusion Detection Pipeline...")
    
    # Define absolute paths based on where this orchestrator script lives (Root)
    ROOT_DIR = Path(__file__).resolve().parent
    SRC_DIR = ROOT_DIR / "src"
    BASH_DIR = ROOT_DIR / "bash_scripts"
    # Do not buffer python's outputs
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    # Verify the directories actually exist before trying to run things inside them
    if not SRC_DIR.exists() or not BASH_DIR.exists():
        print(f"[{now()}] Fatal Error: Could not find 'src' or 'bash_scripts' directories in {ROOT_DIR}")
        sys.exit(1)

    # ==========================================
    # STEP 1: RUN BLOCKING SETUP SCRIPT
    # ==========================================
    print(f"[{now()}] Running setup_dirs.sh...")
    try:
        # cwd=BASH_DIR ensures the script runs exactly as if you 'cd'd into bash_scripts first
        subprocess.run(["bash", "setup_dirs.sh"], cwd=BASH_DIR, check=True)
        print(f"[{now()}] Directories verified/created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[{now()}] Fatal Error: setup_dirs.sh failed with exit code {e.returncode}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[{now()}] Fatal Error: Could not find 'setup_dirs.sh' in {BASH_DIR}")
        sys.exit(1)

    # ==========================================
    # STEP 2: DEFINE CONTINUOUS BACKGROUND TASKS
    # ==========================================
    # Using sys.executable dynamically passes the exact Python path down to the child scripts,
    # ensuring they stay safely inside a virtual environment if the orchestrator was launched in one.
    background_tasks = [
        {"name": "Packet Sniffer",    "cmd": ["sudo", "bash", "sniff_rotate.sh"], "cwd": BASH_DIR, "is_sudo": True},
        {"name": "PCAP Extractor",    "cmd": [sys.executable, "pcap_to_csv_daemon.py"],    "cwd": SRC_DIR,  "is_sudo": False},
        {"name": "Model Classifier",  "cmd": [sys.executable, "model_classification.py"], "cwd": SRC_DIR,  "is_sudo": False}
    ]
    
    processes = []
    
    try:
        for task in background_tasks:
            print(f"[{now()}] Launching {task['name']}...")
            
            # Launch the process in its designated directory
            p = subprocess.Popen(task["cmd"], cwd=task["cwd"], env=env)
            processes.append((task["name"], p, task["is_sudo"]))
            
            # Stagger the launches by 2 seconds to let the pipeline breathe
            time.sleep(2) 

        print(f"\n[{now()}] +---------------------------------------------------+")
        print(f"[{now()}] | ALL PIPELINE COMPONENTS ARE RUNNING.              |")
        print(f"[{now()}] | Press Ctrl+C at any time to stop the pipeline.    |")
        print(f"[{now()}] +---------------------------------------------------+\n")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n[{now()}] Keyboard interrupt received. Shutting down the pipeline gracefully...")
    except Exception as e:
        print(f"\n[{now()}] Pipeline error: {e}")
    finally:
        # ==========================================
        # STEP 3: CLEANUP & TERMINATION
        # ==========================================
        for name, p, is_sudo in processes:
            if p.poll() is None:  
                print(f"[{now()}] Terminating {name} (PID: {p.pid})...")
                if is_sudo:
                    subprocess.run(["sudo", "kill", str(p.pid)], stderr=subprocess.DEVNULL)
                else:
                    p.terminate()
                p.wait() 
                
        print(f"[{now()}] Pipeline shutdown complete. All background tasks stopped.")

if __name__ == "__main__":
    main()