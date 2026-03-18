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
CLEANED_DIR = Path("../data/csvs")
REPORTS_DIR = Path("../data/reports")
MODEL_DIR = Path("../models")

POLL_INTERVAL = 20     
PROCESSED_DB = REPORTS_DIR / "inference_processed.json"

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

def run_inference(file_path: Path, models: dict):
    print(f"\n[{now()}] Analyzing {file_path.name}...")
    
    try:
        # Load the pre-optimized CSV
        df = pd.read_csv(file_path, low_memory=False)
    except Exception as e:
        print(f"Error reading {file_path.name}: {e}")
        return False

    if df.empty:
        print("Dataframe is empty. Skipping.")
        return True

    # Force the exact column order required by the Random Forest
    try:
        X_live = df[models['features']]
    except KeyError as e:
        print(f"CRITICAL ERROR: Cleaned CSV is missing expected training features: {e}")
        return False

    # Run Predictions directly on the NumPy array for high speed
    multi_preds_encoded = models['rf_multi'].predict(X_live)
    
    # Decode Multi-Class Predictions
    multi_preds_decoded = models['label_encoder'].inverse_transform(multi_preds_encoded)

    # Fast NumPy Vectorized math
    total_flows = len(multi_preds_decoded)
    
    # Capitalize 'Benign' or 'benign' robustly using numpy string operations
    # Assumes anything not containing 'benign' is an attack
    is_benign = np.char.find(np.char.lower(multi_preds_decoded.astype(str)), 'benign') != -1
    attacks_detected = total_flows - np.sum(is_benign)

    # Generate Report
    report_lines = [
        "=" * 42,
        f"INFERENCE REPORT: {file_path.name}",
        f"GENERATED AT: {now()}",
        "=" * 42,
        f"Total Flows Analyzed: {total_flows}",
        "-" * 42
    ]

    if attacks_detected > 0:
        pct = (attacks_detected / total_flows) * 100
        report_lines.append(f"STATUS: ALERT - {attacks_detected} attacks detected ({pct:.2f}% of traffic).")
    else:
        report_lines.append("STATUS: NORMAL - No attacks detected.")

    report_lines.append("\n--- ATTACK TYPE SUMMARY ---")
    
    # Use NumPy unique for fast counting (bypassing pandas Series overhead)
    unique_attacks, counts = np.unique(multi_preds_decoded, return_counts=True)
    for attack_type, count in zip(unique_attacks, counts):
        report_lines.append(f"Type [{attack_type}]: {count} flows")

    report_lines.append("\n--- DETAILED LOG (First 10 Flows) ---")
    for i in range(min(10, total_flows)):
        report_lines.append(f"Row {i:06d} -> Flagged as: {multi_preds_decoded[i]}")

    # Save Report
    report_name = f"report_{file_path.stem}.txt"
    report_path = REPORTS_DIR / report_name
    report_path.write_text("\n".join(report_lines))
    
    print(f"[{now()}] Report saved: {report_path.name}")
    return True

def main():
    ensure_dirs_exist()
    processed = load_processed()
    
    print(f"[{now()}] Loading Model into memory...")
    try:
        # Load raw columns, but strip the targets (label1, label2) so we don't look for them in live data
        raw_columns = joblib.load(MODEL_DIR / "training_columns.pkl")
        expected_features = [c for c in raw_columns if c not in ["label1", "label2"]]
        
        models = {
            'features': expected_features,
            'label_encoder': joblib.load(MODEL_DIR / "label_encoder.pkl"),
            'rf_multi': joblib.load(MODEL_DIR / "rf_multi_model.pkl")
        }
    except Exception as e:
        print(f"Failed to load models. Did you save them in the training script? Error: {e}")
        return

    print(f"[{now()}] Listening for cleaned CSVs in {CLEANED_DIR}...")
    
    try:
        while True:
            for p in sorted(CLEANED_DIR.glob("*.cleaned.csv")):
                if p.name not in processed:
                    time.sleep(1) # Wait briefly for file write to complete
                    success = run_inference(p, models)
                    if success:
                        processed.add(p.name)
                        save_processed(processed)
            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print(f"\n[{now()}] Shutting down Inference Engine.")
        save_processed(processed)

if __name__ == "__main__":
    main()