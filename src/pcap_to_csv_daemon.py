#!/usr/bin/env python3

import time
import json
import re
import sys
from pathlib import Path
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP, UDP
import joblib

# ==========================================
# CONFIGURATION
# ==========================================
ROOT_DIR = Path(__file__).resolve().parent.parent
PCAP_DIR = ROOT_DIR / "data" / "pcaps"
CLEANED_DIR = ROOT_DIR / "data" / "csvs"
MODELS_DIR = ROOT_DIR / "models"
COLUMNS_PKL = MODELS_DIR / "training_columns.pkl"

MASTER_CSV = CLEANED_DIR / "master_flows.csv"

POLL_INTERVAL = 5
STABLE_WAIT = 1
SNIFFER_DURATION = 20
SAFETY_MARGIN = 2
FLOW_TIMEOUT_SEC = 60.0  # Remove flows inactive for this long

PROCESSED_DB = CLEANED_DIR / "processed_pcaps.json"

# Extra tracking columns not used by the ML model
META_COLS = ['meta_last_seen', 'meta_terminated']

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_dirs():
    for d in [PCAP_DIR, CLEANED_DIR, MODELS_DIR]:
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)

def load_expected_columns():
    if not COLUMNS_PKL.exists():
        print(f"[{now()}] FATAL ERROR: Could not find {COLUMNS_PKL}.", flush=True)
        sys.exit(1)
    try:
        columns = joblib.load(COLUMNS_PKL)
        columns = [c for c in columns if c not in ["label1", "label2"]]
        print(f"[{now()}] Successfully loaded {len(columns)} expected features.", flush=True)
        return columns
    except Exception as e:
        print(f"[{now()}] FATAL ERROR: Failed to load columns pickle: {e}", flush=True)
        sys.exit(1)

def load_processed():
    if PROCESSED_DB.exists():
        text = PROCESSED_DB.read_text().strip()
        if not text:
            return set()
        try:
            return set(json.loads(text))
        except Exception:
            return set()
    return set()

def save_processed(p):
    PROCESSED_DB.write_text(json.dumps(list(p)))

def parse_time_from_filename(name):
    m = re.search(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", name)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(), "%Y-%m-%d_%H-%M-%S")
    except:
        return None

def stable_ready_files(processed):
    ready = []
    nowdt = datetime.now()

    for f in PCAP_DIR.glob("*.pcap"):
        if f.name in processed:
            continue
        start = parse_time_from_filename(f.name)
        if start and nowdt < start + timedelta(seconds=SNIFFER_DURATION + SAFETY_MARGIN):
            continue
        try:
            s1 = f.stat().st_size
            time.sleep(STABLE_WAIT)
            s2 = f.stat().st_size
            if s1 == s2 and s1 > 0:
                ready.append(f)
        except FileNotFoundError:
            continue
    return ready

def safe_std(values):
    return float(np.std(values)) if len(values) > 1 else 0.0

def process_pcap(path, expected_columns):
    try:
        packets = rdpcap(str(path))
    except Exception as e:
        print(f"[{now()}] Failed to read {path.name}: {e}", flush=True)
        return pd.DataFrame(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port'] + META_COLS + expected_columns)
    
    flows = {}
    
    for pkt in packets:
        if IP not in pkt and IPv6 not in pkt:
            continue
            
        is_ipv6 = IPv6 in pkt
        ip_layer = pkt[IPv6] if is_ipv6 else pkt[IP]
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.nh if is_ipv6 else ip_layer.proto
        
        src_port, dst_port = 0, 0
        if TCP in pkt:
            src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
            
        flow_key = tuple(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"]) + [str(proto)])
        
        if flow_key not in flows:
            flows[flow_key] = {"pkts": [], "anchor_src": src_ip}
        flows[flow_key]["pkts"].append(pkt)

    flow_records = []
    
    for flow_key, data in flows.items():
        pkts = data["pkts"]
        anchor_src = data["anchor_src"]
        first_pkt = pkts[0]
        is_ipv6_pkt = IPv6 in first_pkt
        ip_layer_pkt = first_pkt[IPv6] if is_ipv6_pkt else first_pkt[IP]
        
        f_src_ip = ip_layer_pkt.src
        f_dst_ip = ip_layer_pkt.dst
        f_src_port, f_dst_port = 0, 0
        if TCP in first_pkt:
            f_src_port, f_dst_port = first_pkt[TCP].sport, first_pkt[TCP].dport
        elif UDP in first_pkt:
            f_src_port, f_dst_port = first_pkt[UDP].sport, first_pkt[UDP].dport

        times = [float(p.time) for p in pkts]
        sizes = [len(p) for p in pkts]
        ip_lengths = [len(p[IPv6]) if IPv6 in p else p[IP].len for p in pkts]
        header_lengths = [40 if IPv6 in p else p[IP].ihl * 4 for p in pkts]
        payload_lengths = [sizes[i] - header_lengths[i] for i in range(len(pkts))]
        
        frag_count = 0
        for p in pkts:
            if IP in p:
                try: 
                    flag_val = int(p[IP].flags)
                    if p[IP].frag > 0 or (flag_val & 0x1):
                        frag_count += 1
                except: pass
                
        time_deltas = [times[i] - times[i-1] for i in range(1, len(times))] if len(times) > 1 else [0.0]
        interval_packets = float(np.mean(time_deltas))
        
        syn_c = ack_c = psh_c = urg_c = fin_c = rst_c = 0
        for p in pkts:
            if TCP in p:
                flags = p[TCP].flags
                syn_c += 1 if 'S' in flags else 0
                ack_c += 1 if 'A' in flags else 0
                psh_c += 1 if 'P' in flags else 0
                urg_c += 1 if 'U' in flags else 0
                fin_c += 1 if 'F' in flags else 0
                rst_c += 1 if 'R' in flags else 0

        src_pkts_count = sum(1 for p in pkts if (p[IPv6] if IPv6 in p else p[IP]).src == anchor_src)
        dst_pkts_count = len(pkts) - src_pkts_count

        record = {
            'src_ip': f_src_ip, 'dst_ip': f_dst_ip, 'src_port': f_src_port, 'dst_port': f_dst_port,
            
            # Metadata for pruning
            'meta_last_seen': float(max(times)),
            'meta_terminated': 1.0 if (fin_c > 0 or rst_c > 0) else 0.0,
            
            'network_fragmented-packets': float(frag_count),
            'network_header-length_avg': float(np.mean(header_lengths)),
            'network_header-length_max': float(np.max(header_lengths)),
            'network_header-length_min': float(np.min(header_lengths)),
            'network_header-length_std_deviation': safe_std(header_lengths),
            
            'network_interval-packets': interval_packets,
            
            'network_ip-length_avg': float(np.mean(ip_lengths)),
            'network_ip-length_max': float(np.max(ip_lengths)),
            'network_ip-length_min': float(np.min(ip_lengths)),
            'network_ip-length_std_deviation': safe_std(ip_lengths),
            
            'network_packet-size_avg': float(np.mean(sizes)),
            'network_packet-size_max': float(np.max(sizes)),
            'network_packet-size_min': float(np.min(sizes)),
            'network_packet-size_std_deviation': safe_std(sizes),
            
            'network_packets_all_count': float(len(pkts)),
            'network_packets_dst_count': float(dst_pkts_count),
            'network_packets_src_count': float(src_pkts_count),
            
            'network_payload-length_avg': float(np.mean(payload_lengths)),
            'network_payload-length_max': float(np.max(payload_lengths)),
            'network_payload-length_min': float(np.min(payload_lengths)),
            'network_payload-length_std_deviation': safe_std(payload_lengths),
            
            'network_tcp-flags-ack_count': float(ack_c),
            'network_tcp-flags-psh_count': float(psh_c),
            'network_tcp-flags-syn_count': float(syn_c),
            'network_tcp-flags-urg_count': float(urg_c),
            
            'network_time-delta_avg': float(np.mean(time_deltas)),
            'network_time-delta_max': float(np.max(time_deltas)),
            'network_time-delta_min': float(np.min(time_deltas)),
            'network_time-delta_std_deviation': safe_std(time_deltas)
        }
        flow_records.append(record)

    df = pd.DataFrame(flow_records) if flow_records else pd.DataFrame(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port'] + META_COLS + expected_columns)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    metadata_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
    numeric_cols = df.columns.difference(metadata_cols)
    if not numeric_cols.empty:
        df[numeric_cols] = df[numeric_cols].fillna(0.0)
    
    for col in expected_columns:
        if col not in df.columns: df[col] = 0.0
            
    return df[metadata_cols + META_COLS + expected_columns]

def merge_stateful_dataframes(master_df, new_df, expected_columns):
    """Mathematically merges two processed dataframes to update long-lived flows."""
    idx_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
    
    # Ensure master_df has meta columns if it was created before this update
    for col in META_COLS:
        if col not in master_df.columns:
            master_df[col] = 0.0

    master_df.set_index(idx_cols, inplace=True)
    new_df.set_index(idx_cols, inplace=True)

    common_idx = master_df.index.intersection(new_df.index)
    only_old_idx = master_df.index.difference(new_df.index)
    only_new_idx = new_df.index.difference(master_df.index)

    result_df = pd.DataFrame(index=master_df.index.union(new_df.index), columns=META_COLS + expected_columns)

    # 1. Direct copy for flows only present in one timeframe
    for col in META_COLS + expected_columns:
        result_df.loc[only_old_idx, col] = master_df.loc[only_old_idx, col]
        result_df.loc[only_new_idx, col] = new_df.loc[only_new_idx, col]

    # 2. Mathematical Merge for overlapping flows
    if not common_idx.empty:
        old_c = master_df.loc[common_idx]
        new_c = new_df.loc[common_idx]

        # Handle Metadata Updates (Latest seen time, check if recently terminated)
        result_df.loc[common_idx, 'meta_last_seen'] = np.maximum(old_c['meta_last_seen'], new_c['meta_last_seen'])
        result_df.loc[common_idx, 'meta_terminated'] = np.maximum(old_c['meta_terminated'], new_c['meta_terminated'])

        n1 = old_c['network_packets_all_count'].astype(float)
        n2 = new_c['network_packets_all_count'].astype(float)
        n_total = n1 + n2

        # Time deltas have N-1 counts
        t_n1 = np.maximum(1, n1 - 1)
        t_n2 = np.maximum(1, n2 - 1)
        t_total = t_n1 + t_n2

        # Aggregate Sums
        sum_cols = [
            'network_fragmented-packets', 'network_packets_all_count', 'network_packets_dst_count',
            'network_packets_src_count', 'network_tcp-flags-ack_count', 'network_tcp-flags-psh_count',
            'network_tcp-flags-syn_count', 'network_tcp-flags-urg_count'
        ]
        for col in sum_cols:
            result_df.loc[common_idx, col] = old_c[col] + new_c[col]

        # Aggregate Maxes & Mins
        for col in [c for c in expected_columns if c.endswith('_max')]:
            result_df.loc[common_idx, col] = np.maximum(old_c[col], new_c[col])
        for col in [c for c in expected_columns if c.endswith('_min')]:
            result_df.loc[common_idx, col] = np.minimum(old_c[col], new_c[col])

        # Aggregate Averages and Std Deviations
        feature_bases = ['network_header-length', 'network_ip-length', 'network_packet-size', 'network_payload-length']
        for base in feature_bases:
            mu1, std1 = old_c[f'{base}_avg'], old_c[f'{base}_std_deviation']
            mu2, std2 = new_c[f'{base}_avg'], new_c[f'{base}_std_deviation']

            mu_combined = ((n1 * mu1) + (n2 * mu2)) / n_total
            result_df.loc[common_idx, f'{base}_avg'] = mu_combined

            v_combined = ((std1**2 * n1) + (std2**2 * n2) + (n1 * n2 / n_total) * (mu1 - mu2)**2) / n_total
            result_df.loc[common_idx, f'{base}_std_deviation'] = np.sqrt(v_combined)

        # Time-deltas require their own count denominator (t_n)
        base = 'network_time-delta'
        mu1, std1 = old_c[f'{base}_avg'], old_c[f'{base}_std_deviation']
        mu2, std2 = new_c[f'{base}_avg'], new_c[f'{base}_std_deviation']

        mu_combined = ((t_n1 * mu1) + (t_n2 * mu2)) / t_total
        result_df.loc[common_idx, f'{base}_avg'] = mu_combined
        
        v_combined = ((std1**2 * t_n1) + (std2**2 * t_n2) + (t_n1 * t_n2 / t_total) * (mu1 - mu2)**2) / t_total
        result_df.loc[common_idx, f'{base}_std_deviation'] = np.sqrt(v_combined)
        result_df.loc[common_idx, 'network_interval-packets'] = mu_combined

    result_df.reset_index(inplace=True)
    return result_df

def update_master_csv(new_df, expected_columns):
    if new_df.empty:
        return

    if not MASTER_CSV.exists():
        updated_df = new_df
    else:
        master_df = pd.read_csv(MASTER_CSV)
        updated_df = merge_stateful_dataframes(master_df, new_df, expected_columns)
    
    # --- PRUNING PHASE ---
    initial_count = len(updated_df)
    if not updated_df.empty and 'meta_last_seen' in updated_df.columns:
        # Determine current time context (latest packet time seen across all flows)
        global_latest_time = updated_df['meta_last_seen'].max()
        
        # 1. Remove flows that have cleanly terminated via FIN or RST
        updated_df = updated_df[updated_df['meta_terminated'] == 0.0]
        
        # 2. Remove flows that have been inactive for more than FLOW_TIMEOUT_SEC
        updated_df = updated_df[(global_latest_time - updated_df['meta_last_seen']) <= FLOW_TIMEOUT_SEC]
        
    pruned_count = initial_count - len(updated_df)
    if pruned_count > 0:
        print(f"[{now()}] Pruned {pruned_count} terminated or inactive flows from state.", flush=True)
    
    # Final cleanup before saving
    updated_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    updated_df.fillna(0.0, inplace=True)
    
    # Save the dataframe, making sure we don't accidentally drop empty index if 100% of flows were pruned
    updated_df.to_csv(MASTER_CSV, index=False)

def run_daemon():
    ensure_dirs()
    expected_columns = load_expected_columns()
    processed = load_processed()
    print(f"[{now()}] Unified Data Processor listening on {PCAP_DIR}...", flush=True)

    try:
        while True:
            files = stable_ready_files(processed)

            for p in files:
                print(f"[{now()}] Processing {p.name}", flush=True)
                df = process_pcap(p, expected_columns)
                update_master_csv(df, expected_columns)
                print(f"[{now()}] Updated state in {MASTER_CSV.name}", flush=True)

                processed.add(p.name)
                save_processed(processed)

            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print(f"\n[{now()}] Interrupted by user. Saving state and exiting.", flush=True)
        save_processed(processed)

if __name__ == "__main__":
    run_daemon()