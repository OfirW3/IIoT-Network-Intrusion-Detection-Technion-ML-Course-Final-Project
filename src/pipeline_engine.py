#!/usr/bin/env python3

import subprocess
import time
import sys
import multiprocessing
from pathlib import Path
from datetime import datetime
import os

# Dynamically search for root dir
ROOT_DIR = Path(__file__).resolve().parent.parent

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import functions from other scripts
from src.pcap_to_csv_daemon import run_daemon
from src.model_classification import classify_traffic

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_engine():
    print(f"[{now()}] Starting the NIDS Backend Engine...")
    
    BASH_DIR = ROOT_DIR / "bash_scripts"
    
    # Verify the bash directory exists
    if not BASH_DIR.exists():
        print(f"[{now()}] Fatal Error: Could not find 'bash_scripts' directory in {ROOT_DIR}")
        sys.exit(1)

    # ==========================================
    #          RUN BLOCKING SETUP SCRIPT
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
    #       LAUNCH CONTINUOUS BACKGROUND TASKS
    # ==========================================
    # 1. Launch the Bash Packet Sniffer via Subprocess
    print(f"[{now()}] Launching Packet Sniffer (sniff_rotate.sh)...")
    # We use sudo here just to be safe, though the engine itself is likely run with sudo by the GUI
    sniffer_process = subprocess.Popen(["sudo", "bash", "sniff_rotate.sh"], cwd=BASH_DIR)
    
    # Stagger the launches by a second to let the pipeline breathe
    time.sleep(1) 

    # 2. Launch the Python Daemons using Multiprocessing
    print(f"[{now()}] Launching PCAP Extractor Daemon...")
    daemon_proc = multiprocessing.Process(target=run_daemon)
    daemon_proc.start()
    
    time.sleep(1)

    print(f"[{now()}] Launching Model Classifier...")
    classifier_proc = multiprocessing.Process(target=classify_traffic)
    classifier_proc.start()

    print(f"\n[{now()}] +---------------------------------------------------+")
    print(f"[{now()}] | ALL BACKEND ENGINE COMPONENTS ARE RUNNING.        |")
    print(f"[{now()}] | Managed by GUI. Press Ctrl+C in terminal to stop. |")
    print(f"[{now()}] +---------------------------------------------------+\n")

    try:
        # Keep the main process alive while the background tasks run
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n[{now()}] Shutdown signal received. Stopping backend engine gracefully...")
    except Exception as e:
        print(f"\n[{now()}] Engine error: {e}")
    finally:
        # ==========================================
        #       CLEANUP & TERMINATION
        # ==========================================
        print(f"[{now()}] Terminating Python Daemons...")
        if daemon_proc.is_alive():
            daemon_proc.terminate()
            daemon_proc.join()
            
        if classifier_proc.is_alive():
            classifier_proc.terminate()
            classifier_proc.join()

        print(f"[{now()}] Terminating Packet Sniffer (PID: {sniffer_process.pid})...")
        if sniffer_process.poll() is None:
            # Sudo kill ensures the bash script dies even if it spawned child processes
            subprocess.run(["sudo", "kill", str(sniffer_process.pid)], stderr=subprocess.DEVNULL)
            sniffer_process.wait()

        print(f"[{now()}] Backend engine shutdown complete.")

if __name__ == "__main__":
    run_engine()