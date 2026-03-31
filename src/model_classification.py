#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import time
import json
import os
import pandas as pd
import numpy as np
import joblib

# ==========================================
# CONFIGURATION
# ==========================================
ROOT_DIR = Path(__file__).resolve().parent.parent
CLEANED_DIR = ROOT_DIR / "data" / "csvs"
REPORTS_DIR = ROOT_DIR / "data" / "reports"
MODEL_DIR = ROOT_DIR / "models"

MASTER_CSV = CLEANED_DIR / "master_flows.csv"
STATE_FILE = REPORTS_DIR / "inference_state.txt"

POLL_INTERVAL = 20     

# Common column names
SRC_IP_COLS = ['src_ip']
DST_IP_COLS = ['dst_ip']
SRC_PORT_COLS = ['src_port']
DST_PORT_COLS = ['dst_port']

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_dirs_exist():
    for d in [CLEANED_DIR, REPORTS_DIR, MODEL_DIR]:
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)

def load_last_mtime():
    """Loads the last modified timestamp of the master CSV we processed."""
    if STATE_FILE.exists():
        try:
            return float(STATE_FILE.read_text().strip())
        except Exception:
            pass
    return 0.0

def save_last_mtime(mtime: float):
    STATE_FILE.write_text(str(mtime))

def get_col_val(row, possible_cols):
    for col in possible_cols:
        if col in row.index and pd.notna(row[col]):
            return str(row[col]).replace('.0', '')
    return "?"

def run_inference(file_path: Path, models: dict, run_id: str):
    print(f"\n[{now()}] Analyzing current state of {file_path.name}...", flush=True)
    
    try:
        df = pd.read_csv(file_path, low_memory=False)
    except Exception as e:
        print(f"Error reading {file_path.name}: {e}", flush=True)
        return False

    if df.empty:
        print("Dataframe is empty. Skipping.", flush=True)
        return True

    # This drops the IPs and Ports specifically for the model inference
    try:
        X_live = df[models['features']]
    except KeyError as e:
        print(f"CRITICAL ERROR: Cleaned CSV is missing expected training features: {e}", flush=True)
        return False

    multi_preds_encoded = models['rf_multi'].predict(X_live)
    multi_preds_decoded = models['label_encoder'].inverse_transform(multi_preds_encoded)
    
    total_flows = len(multi_preds_decoded)
    is_benign = np.char.find(np.char.lower(multi_preds_decoded.astype(str)), 'benign') != -1
    attacks_detected = total_flows - np.sum(is_benign)

    report_lines = [
        "=" * 80,
        f"INFERENCE REPORT: {file_path.name}",
        f"RUN ID: {run_id}",
        f"GENERATED AT: {now()}",
        "=" * 80,
        f"Total Active Flows Analyzed: {total_flows}",
        "-" * 80
    ]

    if attacks_detected > 0:
        pct = (attacks_detected / total_flows) * 100
        report_lines.append(f"STATUS: ALERT - {attacks_detected} attacks detected ({pct:.2f}% of traffic).")
    else:
        report_lines.append("STATUS: NORMAL - No attacks detected.")

    report_lines.append("\n--- TRAFFIC TYPE SUMMARY ---")
    unique_types, counts = np.unique(multi_preds_decoded, return_counts=True)
    for traffic_type, count in zip(unique_types, counts):
        report_lines.append(f"Type [{traffic_type}]: {count} flows")

    report_lines.append("\n--- DETAILED FLOW LOG ---")
    
    # Create comprehensive dataframe for ALL flows (benign + attacks)
    results_df = df.copy()
    results_df['predicted_traffic_type'] = multi_preds_decoded
    
    # Move 'predicted_traffic_type' to the very front of the CSV for readability
    cols = results_df.columns.tolist()
    cols.insert(0, cols.pop(cols.index('predicted_traffic_type')))
    results_df = results_df[cols]
    
    results_csv_path = REPORTS_DIR / f"full_log_{run_id}.csv"
    results_df.to_csv(results_csv_path, index=False)
    report_lines.append(f"-> Full classification details saved to: {results_csv_path.name}\n")

    # Print a preview of the flows to the GUI/Console
    MAX_DISPLAY = 50
    for idx in range(min(total_flows, MAX_DISPLAY)):
        traffic_type = multi_preds_decoded[idx]
        row = df.iloc[idx]
        
        src_ip = get_col_val(row, SRC_IP_COLS)
        dst_ip = get_col_val(row, DST_IP_COLS)
        src_port = get_col_val(row, SRC_PORT_COLS)
        dst_port = get_col_val(row, DST_PORT_COLS)
        
        report_lines.append(f"Row {idx:06d} | TYPE: {traffic_type:<10} | SRC: {src_ip}:{src_port:<5}  ->  DST: {dst_ip}:{dst_port}")
        
    if total_flows > MAX_DISPLAY:
        report_lines.append(f"... and {total_flows - MAX_DISPLAY} more flows. (See full log CSV)")

    report_lines.append("=" * 80 + "\n")

    full_report_text = "\n".join(report_lines)
    print(full_report_text, flush=True)

    report_name = f"report_{run_id}.txt"
    report_path = REPORTS_DIR / report_name
    report_path.write_text(full_report_text)
    
    return True

def classify_traffic():
    ensure_dirs_exist()
    last_mtime = load_last_mtime()
    
    print(f"[{now()}] Loading Model into memory...", flush=True)
    try:
        raw_columns = joblib.load(MODEL_DIR / "training_columns.pkl")
        expected_features = [c for c in raw_columns if c not in ["label1", "label2"]]
        
        models = {
            'features': expected_features,
            'label_encoder': joblib.load(MODEL_DIR / "label_encoder.pkl"),
            'rf_multi': joblib.load(MODEL_DIR / "rf_multi_model.pkl")
        }
    except Exception as e:
        print(f"Failed to load models. Did you save them in the training script? Error: {e}", flush=True)
        return

    print(f"[{now()}] Monitoring {MASTER_CSV.name} for state changes...", flush=True)
    
    try:
        while True:
            if MASTER_CSV.exists():
                current_mtime = MASTER_CSV.stat().st_mtime
                
                # If the file has been modified since we last checked
                if current_mtime > last_mtime:
                    # Brief pause to ensure the writer script has finished saving the CSV
                    time.sleep(1) 
                    
                    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
                    success = run_inference(MASTER_CSV, models, run_id)
                    
                    if success:
                        last_mtime = current_mtime
                        save_last_mtime(last_mtime)
                        
            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print(f"\n[{now()}] Shutting down Inference Engine.", flush=True)
        save_last_mtime(last_mtime)

if __name__ == "__main__":
    classify_traffic()