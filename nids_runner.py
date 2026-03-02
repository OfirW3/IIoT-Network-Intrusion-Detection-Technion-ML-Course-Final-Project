import os
import time
import glob
import shutil
import subprocess
import pandas as pd
import joblib
from datetime import datetime

# CONFIGURATION
INTERFACE = os.getenv("INTERFACE", "eth0")  # Uses eth0 by default, can be overridden
CHUNK_TIME = "10"                           # Rotate PCAP every 30 seconds
MODEL_PATH = "rf_model.pkl"
CIC_BIN_PATH = "./CICFlowMeter/bin/cfm"     # Path inside the Docker container

DIRS = {
    "staging": "data/staging",
    "processing": "data/processing",
    "csvs": "data/csvs",
    "archive": "data/archive"
}

# Filtering keywords
FATAL_KEYWORDS = ["mac", "port", "addr", "id", "uuid", "token", "serial", "socket", "session", "ip_src", "ip_dst", "src_ip", "dst_ip"]
TOXIC_KEYWORDS = ["time", "date", "timestamp", "ttl", "window", "mss", "seq", "ack"]
SAFE_KEYWORDS = ["duration", "interval", "rate", "delta", "mean", "std", "avg"]

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# PIPELINE FUNCTIONS
def setup_directories():
    """Ensure all working directories exist"""
    for d in DIRS.values():
        os.makedirs(d, exist_ok=True)

def start_tcpdump():
    """Launch tcpdump in the background to capture rolling PCAPs"""
    print(f"[{now()}] Starting packet capture on interface {INTERFACE}...")
    pcap_pattern = os.path.join(DIRS['staging'], "chunk_%Y-%m-%d_%H-%M-%S.pcap")
    
    cmd = [
        "tcpdump", "-i", INTERFACE, "-n", "-w", pcap_pattern, "-G", CHUNK_TIME
    ]
    # Use popen for running asynchronously in the background
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def filter_features(df):
    """Applies the exact same feature dropping logic used during training"""
    df.columns = [c.lower().strip() for c in df.columns]
    
    feature_cols = []
    for c in df.columns:
        if "label" in c: continue
        
        is_fatal = any(fatal in c for fatal in FATAL_KEYWORDS)
        if is_fatal and not ("id" in c and ("width" in c or "valid" in c)):
            continue
            
        is_toxic = any(toxic in c for toxic in TOXIC_KEYWORDS)
        if is_toxic:
            is_safe = any(safe in c for safe in SAFE_KEYWORDS)
            if not is_safe:
                continue
                
        feature_cols.append(c)
        
    return df[feature_cols]

def analyze_csv(csv_path, models):
    """Load the CSV, filter it, and run the RF predictions"""
    try:
        df = pd.read_csv(csv_path)
        if df.empty:
            return

        # Keep a copy for later alerting purposes
        alerts_info = df[['Src IP', 'Dst IP', 'Dst Port', 'Protocol']].copy() if 'Src IP' in df.columns else pd.DataFrame()
        
        # Apply the leakage filter
        X_live = filter_features(df)
        
        # Ensure data is numeric and handle NaNs just like training
        X_live = X_live.apply(pd.to_numeric, errors='coerce').fillna(0)
        
        # Load the binary model from the saved dictionary
        rf_bin = models["binary_model"]
        
        # Allign the collumns based on feature_names_in_
        if hasattr(rf_bin, 'feature_names_in_'):
            # Fill missing columns with 0, drop extra columns, enforce order (Maybe will be changed later for better logic)
            for col in rf_bin.feature_names_in_:
                if col not in X_live.columns:
                    X_live[col] = 0
            X_live = X_live[rf_bin.feature_names_in_]
            
        # Run prediction
        predictions = rf_bin.predict(X_live.values)
        
        # Process alerts
        attacks_found = 0
        for i, pred in enumerate(predictions):
            if pred == 1:  # 1 represents Attack based on the training logic
                attacks_found += 1
                if not alerts_info.empty:
                    src = alerts_info.iloc[i]['Src IP']
                    dst = alerts_info.iloc[i]['Dst IP']
                    port = alerts_info.iloc[i]['Dst Port']
                    print(f"[{now()}] MALICIOUS FLOW DETECTED: {src} -> {dst}:{port}")
                else:
                    print(f"[{now()}] MALICIOUS FLOW DETECTED (Row {i})")
                    
        if attacks_found == 0:
            print(f"[{now()}] Clean traffic. {len(predictions)} flows analyzed. No attacks detected.")
        else:
            print(f"[{now()}] WARNING: {attacks_found} malicious flows detected in this chunk")

    except Exception as e:
        print(f"[{now()}] Error analyzing CSV: {e}")

# MAIN POLLING LOOP
def main():
    print(f"[{now()}] === NIDS Docker Container Initializing ===")
    setup_directories()
    
    print(f"[{now()}] Loading Random Forest Models from {MODEL_PATH}...")
    models = joblib.load(MODEL_PATH)
    
    tcpdump_process = start_tcpdump()
    
    print(f"[{now()}] System armed. Watching for traffic chunks...")
    
    # Watch for new PCAPs every 2 seconds
    try:
        while True:
            # Find PCAPs that haven't been modified in the last 3 seconds
            current_time = time.time()
            for pcap in glob.glob(os.path.join(DIRS["staging"], "*.pcap")):
                if current_time - os.path.getmtime(pcap) > 3.0:
                    
                    filename = os.path.basename(pcap)
                    processing_path = os.path.join(DIRS["processing"], filename)
                    
                    # Move to processing directory
                    shutil.move(pcap, processing_path)
                    print(f"\n[{now()}] Processing chunk: {filename}")
                    
                    # Run CICFlowMeter on the finished PCAP
                    subprocess.run(
                        ["bash", CIC_BIN_PATH, processing_path, DIRS["csvs"]],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    
                    # Find the resulting CSV (CICFlowMeter appends "_Flow.csv")
                    csv_filename = filename + "_Flow.csv"
                    csv_path = os.path.join(DIRS["csvs"], csv_filename)
                    
                    # Analyze it with the Random Forest
                    if os.path.exists(csv_path):
                        analyze_csv(csv_path, models)
                        
                        # Cleanup: Move to archive
                        shutil.move(processing_path, os.path.join(DIRS["archive"], filename))
                        shutil.move(csv_path, os.path.join(DIRS["archive"], csv_filename))
                    else:
                        print(f"[{now()}] No flows generated for {filename} (Chunk might be empty).")
                        shutil.move(processing_path, os.path.join(DIRS["archive"], filename))
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print(f"\n[{now()}] KEYBOARD INTERRUPT: Shutting down NIDS...")
        tcpdump_process.terminate()

if __name__ == "__main__":
    main()