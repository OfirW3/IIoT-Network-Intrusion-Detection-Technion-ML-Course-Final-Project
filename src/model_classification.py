#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import time
import json
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

POLL_INTERVAL = 20     
PROCESSED_DB = REPORTS_DIR / "inference_processed.json"

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

def load_processed():
    if PROCESSED_DB.exists():
        try:
            return set(json.loads(PROCESSED_DB.read_text()))
        except Exception:
            pass
    return set()

def save_processed(s):
    PROCESSED_DB.write_text(json.dumps(sorted(list(s))))

def get_col_val(row, possible_cols):
    for col in possible_cols:
        if col in row.index and pd.notna(row[col]):
            return str(row[col]).replace('.0', '')
    return "?"

def run_inference(file_path: Path, models: dict):
    print(f"\n[{now()}] Analyzing {file_path.name}...", flush=True)
    
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
        f"GENERATED AT: {now()}",
        "=" * 80,
        f"Total Flows Analyzed: {total_flows}",
        "-" * 80
    ]

    if attacks_detected > 0:
        pct = (attacks_detected / total_flows) * 100
        report_lines.append(f"STATUS: ALERT - {attacks_detected} attacks detected ({pct:.2f}% of traffic).")
    else:
        report_lines.append("STATUS: NORMAL - No attacks detected.")

    report_lines.append("\n--- ATTACK TYPE SUMMARY ---")
    unique_attacks, counts = np.unique(multi_preds_decoded, return_counts=True)
    for attack_type, count in zip(unique_attacks, counts):
        report_lines.append(f"Type [{attack_type}]: {count} flows")

    report_lines.append("\n--- DETAILED ATTACK LOG ---")
    attack_indices = np.where(~is_benign)[0]
    
    if len(attack_indices) == 0:
        report_lines.append("No attacks detected in this capture.")
    else:
        # Create alert dataframe for alerting on attacks
        alerts_df = df.iloc[attack_indices].copy()
        alerts_df['predicted_attack_type'] = multi_preds_decoded[attack_indices]
        
        # Move 'predicted_attack_type' to the very front of the CSV for readability
        cols = alerts_df.columns.tolist()
        cols.insert(0, cols.pop(cols.index('predicted_attack_type')))
        alerts_df = alerts_df[cols]
        
        alerts_csv_path = REPORTS_DIR / f"alerts_{file_path.stem}.csv"
        alerts_df.to_csv(alerts_csv_path, index=False)
        report_lines.append(f"-> Full alert details saved to: {alerts_csv_path.name}\n")

        # Print attacks list to gui
        MAX_DISPLAY = 50
        for idx in attack_indices[:MAX_DISPLAY]:
            attack_type = multi_preds_decoded[idx]
            row = df.iloc[idx]
            
            src_ip = get_col_val(row, SRC_IP_COLS)
            dst_ip = get_col_val(row, DST_IP_COLS)
            src_port = get_col_val(row, SRC_PORT_COLS)
            dst_port = get_col_val(row, DST_PORT_COLS)
            
            report_lines.append(f"Row {idx:06d} | TYPE: {attack_type:<10} | SRC: {src_ip}:{src_port:<5}  ->  DST: {dst_ip}:{dst_port}")
            
        if len(attack_indices) > MAX_DISPLAY:
            report_lines.append(f"... and {len(attack_indices) - MAX_DISPLAY} more attacks. (See alert CSV)")

    report_lines.append("=" * 80 + "\n")

    full_report_text = "\n".join(report_lines)
    print(full_report_text, flush=True)

    report_name = f"report_{file_path.stem}.txt"
    report_path = REPORTS_DIR / report_name
    report_path.write_text(full_report_text)
    
    return True

def classify_traffic():
    ensure_dirs_exist()
    processed = load_processed()
    
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

    print(f"[{now()}] Listening for cleaned CSVs in {CLEANED_DIR}...", flush=True)
    
    try:
        while True:
            for p in sorted(CLEANED_DIR.glob("*.cleaned.csv")):
                if p.name not in processed:
                    time.sleep(1) 
                    success = run_inference(p, models)
                    if success:
                        processed.add(p.name)
                        save_processed(processed)
            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print(f"\n[{now()}] Shutting down Inference Engine.", flush=True)
        save_processed(processed)

if __name__ == "__main__":
    classify_traffic()