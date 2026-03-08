#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import time
import json
import pandas as pd

# CONFIG
RAW_DIR = Path("../data/raw_csvs")
OUT_DIR = Path("../data/cleaned_csvs")
POLL_INTERVAL = 20     # seconds between directory scans
STABLE_WAIT = 2        # seconds to wait to confirm file size stability
PROCESSED_DB = OUT_DIR / "processed_files.json"

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# filtering lists (expanded to drop log metrics and leaking features)
FATAL_KEYWORDS = [
    # Identifiers & Hardware
    "mac", "port", "addr", "id", "uuid", "token", "serial", "socket", "session",
    "device", "host",
    # Specific network routing
    "ip_src", "ip_dst", "src_ip", "dst_ip", 
    # Label and classification leaks
    "label", "attack", "class", "category", "status",
    # Extraneous host logging metrics (all zeros anyway)
    "log"
]

TOXIC_KEYWORDS = [
    # Metadata that could be memorized by the model
    "time", "date", "timestamp", "ttl", "window", "mss", "seq", "ack"
]

SAFE_KEYWORDS = ["duration", "interval", "rate", "delta", "mean", "std", "avg", "count", "length", "size"]

def ensure_dirs_exist():
    """Do not create directories — only verify they exist."""
    if not RAW_DIR.exists():
        raise RuntimeError(f"Missing required directory: {RAW_DIR} (create it before running).")
    if not OUT_DIR.exists():
        raise RuntimeError(f"Missing required directory: {OUT_DIR} (create it before running).")

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
    """
    Efficient stability check:
    - collect candidate files not yet processed
    - record sizes, wait STABLE_WAIT seconds, recheck sizes
    - return list of stable files (size unchanged and >0)
    """
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
            s2 = p.stat().st_size
        except FileNotFoundError:
            continue
        if s1 == s2 and s1 > 0:
            stable.append(p)
    return sorted(stable)

def select_features(cols):
    """Return list of columns to keep based on anti-leak rules."""
    keep = []
    drop = []
    for c in cols:
        c_l = c.lower().strip()

        # fatal keywords (leaking features and logs)
        is_fatal = False
        for f in FATAL_KEYWORDS:
            if f == "log" and not c_l.startswith("log_"):
                pass
            elif f in c_l:
                # specific safe exceptions if necessary (e.g. valid identifier flags)
                if f == "id" and ("width" in c_l or "valid" in c_l):
                    continue
                is_fatal = True
                break
        
        if c_l.startswith("log_") or is_fatal:
            drop.append(c)
            continue

        # toxic keywords (time/sequence based leaks)
        is_toxic = False
        for t in TOXIC_KEYWORDS:
            if t in c_l:
                is_toxic = True
                break
        if is_toxic:
            is_safe = False
            for s in SAFE_KEYWORDS:
                if s in c_l:
                    is_safe = True
                    break
            if not is_safe:
                drop.append(c)
                continue

        keep.append(c)
    
    return keep, drop

def preprocess_file(path: Path):
    """Read file, filter leaking features, coerce strictly to numeric (NaN->0), write cleaned CSV."""
    print(f"[{now()}] Processing {path.name}")
    try:
        df = pd.read_csv(path, low_memory=False, on_bad_lines="skip")
    except Exception as e:
        print(f"[{now()}] Failed to read {path.name}: {e}")
        return False

    cols_to_keep, dropped = select_features(list(df.columns))
    if not cols_to_keep:
        print(f"[{now()}] No columns to keep for {path.name}; skipping.")
        return False

    df_keep = df[cols_to_keep].copy()

    # Coerce everything remaining to numeric, NaN -> 0
    df_clean = df_keep.apply(pd.to_numeric, errors="coerce").fillna(0)

    # output path: replace ".raw.csv" with ".cleaned.csv"
    out_name = path.name.rsplit(".raw.csv", 1)[0] + ".cleaned.csv"
    out_path = OUT_DIR / out_name
    try:
        df_clean.to_csv(out_path, index=False)
        print(f"[{now()}] Wrote cleaned CSV: {out_path.name}  (kept {len(cols_to_keep)} features, dropped {len(dropped)})")
        return True
    except Exception as e:
        print(f"[{now()}] Failed to write cleaned CSV for {path.name}: {e}")
        return False

def main():
    ensure_dirs_exist()   # will raise if directories missing
    processed = load_processed()
    print(f"[{now()}] Watching {RAW_DIR} (poll every {POLL_INTERVAL}s).")
    try:
        while True:
            ready = stable_files(processed)
            if ready:
                for p in ready:
                    ok = preprocess_file(p)
                    if ok:
                        processed.add(p.name)
                        # save processed DS; may raise if OUT_DIR removed — that's intended
                        save_processed(processed)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print(f"\n[{now()}] Interrupted by user. Saving processed DB and exiting.")
        save_processed(processed)

if __name__ == "__main__":
    main()