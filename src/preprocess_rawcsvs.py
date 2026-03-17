#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import time
import json
import pandas as pd
import joblib

# CONFIG
RAW_DIR = Path("../data/raw_csvs")
OUT_DIR = Path("../data/cleaned_csvs")
MODEL_DIR = Path("../models")
TRAIN_COLS_PATH = MODEL_DIR / "training_columns.pkl"
PROCESSED_DB = OUT_DIR / "processed_files.json"

POLL_INTERVAL = 20
STABLE_WAIT = 2

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_dirs_exist():
    for d in [RAW_DIR, OUT_DIR, MODEL_DIR]:
        if not d.exists():
            raise RuntimeError(f"Missing required directory: {d}")
    if not TRAIN_COLS_PATH.exists():
        raise RuntimeError(f"Missing {TRAIN_COLS_PATH}! Run the training script to generate it.")

def load_processed():
    if PROCESSED_DB.exists():
        try:
            return set(json.loads(PROCESSED_DB.read_text()))
        except Exception:
            return set()
    return set()

def save_processed(s):
    PROCESSED_DB.write_text(json.dumps(sorted(list(s))))

def stable_files(processed):
    candidates = []
    sizes_before = {}
    for p in RAW_DIR.glob("*.raw.csv"):
        if p.name in processed:
            continue
        try:
            sizes_before[p] = p.stat().st_size
        except FileNotFoundError:
            continue

    if not sizes_before:
        return []

    time.sleep(STABLE_WAIT)

    stable = []
    for p, s1 in sizes_before.items():
        try:
            if s1 == p.stat().st_size and s1 > 0:
                stable.append(p)
        except FileNotFoundError:
            continue
    return sorted(stable)

def preprocess_file(path: Path, expected_cols: list):
    print(f"[{now()}] Processing {path.name}")
    try:
        df = pd.read_csv(path, low_memory=False, on_bad_lines="skip")
    except Exception as e:
        print(f"[{now()}] Failed to read {path.name}: {e}")
        return False

    # 1. Ensure all expected training columns exist (fill with 0 if missing from PCAP)
    for col in expected_cols:
        if col not in df.columns:
            df[col] = 0

    # 2. Strictly enforce ONLY the training features (no MACs, no timestamps)
    df_keep = df[expected_cols].copy()

    # 3. Coerce everything to numeric, NaN -> 0
    for col in expected_cols:
        df_keep[col] = pd.to_numeric(df_keep[col], errors="coerce").fillna(0)

    out_name = path.name.rsplit(".raw.csv", 1)[0] + ".cleaned.csv"
    out_path = OUT_DIR / out_name
    try:
        df_keep.to_csv(out_path, index=False)
        print(f"[{now()}] Wrote cleaned CSV: {out_path.name} (Strictly {len(expected_cols)} features)")
        return True
    except Exception as e:
        print(f"[{now()}] Failed to write cleaned CSV for {path.name}: {e}")
        return False

def main():
    ensure_dirs_exist()
    processed = load_processed()
    expected_cols = joblib.load(TRAIN_COLS_PATH)
    
    print(f"[{now()}] Watching {RAW_DIR} (poll every {POLL_INTERVAL}s).")
    try:
        while True:
            ready = stable_files(processed)
            if ready:
                for p in ready:
                    ok = preprocess_file(p, expected_cols)
                    if ok:
                        processed.add(p.name)
                        save_processed(processed)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print(f"\n[{now()}] Interrupted by user. Saving processed DB and exiting.")
        save_processed(processed)

if __name__ == "__main__":
    main()