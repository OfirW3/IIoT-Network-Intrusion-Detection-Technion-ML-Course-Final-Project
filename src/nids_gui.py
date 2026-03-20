#!/usr/bin/env python3
import tkinter as tk
from tkinter import scrolledtext, font
import subprocess
import threading
import queue
import os
import sys
from pathlib import Path

# Dynamically find the project root (parent of the 'src' folder)
ROOT_DIR = Path(__file__).resolve().parent.parent

class NIDSCommandCenter:
    def __init__(self, root):
        self.root = root
        self.root.title("NIDS Command Center")
        self.root.geometry("900x650")
        self.root.configure(bg="#1e1e1e")
        
        self.process = None
        self.log_queue = queue.Queue()
        
        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.poll_logs()

    def setup_ui(self):
        # Fonts
        title_font = font.Font(family="Helvetica", size=16, weight="bold")
        btn_font = font.Font(family="Helvetica", size=11, weight="bold")
        log_font = font.Font(family="Consolas", size=10)

        # Header Frame
        header_frame = tk.Frame(self.root, bg="#1e1e1e")
        header_frame.pack(fill=tk.X, pady=10, padx=20)

        title_lbl = tk.Label(header_frame, text="NIDS Command Center", font=title_font, fg="#ffffff", bg="#1e1e1e")
        title_lbl.pack(side=tk.LEFT)

        self.status_lbl = tk.Label(header_frame, text="Status: OFFLINE", font=btn_font, fg="#9e9e9e", bg="#1e1e1e")
        self.status_lbl.pack(side=tk.RIGHT)

        # Controls Frame
        control_frame = tk.Frame(self.root, bg="#1e1e1e")
        control_frame.pack(fill=tk.X, pady=5, padx=20)

        self.start_btn = tk.Button(control_frame, text="START PIPELINE", font=btn_font, bg="#4CAF50", fg="white", 
                                   activebackground="#45a049", width=20, command=self.start_pipeline)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_btn = tk.Button(control_frame, text="STOP PIPELINE", font=btn_font, bg="#f44336", fg="white", 
                                  activebackground="#da190b", width=20, state=tk.DISABLED, command=self.stop_pipeline)
        self.stop_btn.pack(side=tk.LEFT)

        copy_btn = tk.Button(control_frame, text="COPY LOGS", font=btn_font, bg="#2196F3", fg="white", 
                             activebackground="#0b7dda", width=15, command=self.copy_to_clipboard)
        copy_btn.pack(side=tk.RIGHT)

        # Logs Area
        log_frame = tk.Frame(self.root, bg="#1e1e1e")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(10, 20))

        self.text_area = scrolledtext.ScrolledText(log_frame, font=log_font, bg="#2d2d2d", fg="#e0e0e0", state=tk.DISABLED)
        self.text_area.pack(fill=tk.BOTH, expand=True)

    def log(self, message):
        """Thread-safe logging mechanism using a queue."""
        self.log_queue.put(message)

    def poll_logs(self):
        """Periodically checks the queue for new logs and updates the UI."""
        while not self.log_queue.empty():
            msg = self.log_queue.get_nowait()
            self.text_area.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, msg)
            self.text_area.see(tk.END)
            self.text_area.config(state=tk.DISABLED)
        
        # Check if the backend engine died unexpectedly
        if self.process is not None:
            ret = self.process.poll()
            if ret is not None:
                self.handle_process_exit()

        self.root.after(100, self.poll_logs)

    def read_stdout(self):
        """Reads the backend pipeline's output in real-time."""
        if self.process and self.process.stdout:
            for line in iter(self.process.stdout.readline, b''):
                try:
                    decoded = line.decode("utf-8")
                except UnicodeDecodeError:
                    decoded = line.decode("latin-1", errors="replace")
                self.log(decoded)

    def copy_to_clipboard(self):
        self.root.clipboard_clear()
        self.text_area.config(state=tk.NORMAL)
        logs = self.text_area.get(1.0, tk.END)
        self.text_area.config(state=tk.DISABLED)
        self.root.clipboard_append(logs)
        self.log("\n[GUI] Logs copied to clipboard.\n")

    def start_pipeline(self):
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_lbl.config(text="Status: RUNNING", fg="#4CAF50")
        
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete(1.0, tk.END)
        self.text_area.config(state=tk.DISABLED)
        
        self.log("[GUI] Initializing End-to-End Pipeline...\n")

        # Dynamically point to the backend engine script
        engine_script = ROOT_DIR / "src" / "pipeline_engine.py"
        
        # Absolute path to your virtual environment's python. 
        # Fallback to sys.executable just in case nids_env isn't there.
        python_bin = ROOT_DIR / "nids_env" / "bin" / "python"
        if not python_bin.exists():
            python_bin = sys.executable

        cmd = ["sudo", str(python_bin), str(engine_script)]
        
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1" 

        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
            # Start a background thread so the GUI doesn't freeze while waiting for logs
            threading.Thread(target=self.read_stdout, daemon=True).start()
        except Exception as e:
            self.log(f"\n[GUI FATAL ERROR] {e}\n")
            self.handle_process_exit()

    def stop_pipeline(self):
        if self.process:
            self.log("\n[GUI] Sending graceful interrupt (Ctrl+C) to pipeline via sudo...\n")
            self.stop_btn.config(state=tk.DISABLED)
            self.status_lbl.config(text="Status: SHUTTING DOWN...", fg="#ffd600")
            
            # Update the pkill target to match the new engine name
            subprocess.run(["sudo", "pkill", "-SIGINT", "-f", "pipeline_engine.py"], stderr=subprocess.DEVNULL)

    def handle_process_exit(self):
        self.process = None
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_lbl.config(text="Status: OFFLINE", fg="#9e9e9e")
        self.log("\n[GUI] Pipeline gracefully terminated.\n")

    def on_closing(self):
        if self.process:
            self.stop_pipeline()
        self.root.destroy()

def run_gui():
    """This function initializes and starts the GUI."""
    # This prevents the GUI from scaling weirdly on high-DPI displays
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
        
    root = tk.Tk()
    app = NIDSCommandCenter(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()