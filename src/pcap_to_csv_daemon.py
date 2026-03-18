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

POLL_INTERVAL = 5
STABLE_WAIT = 1
SNIFFER_DURATION = 20
SAFETY_MARGIN = 2

PROCESSED_DB = CLEANED_DIR / "processed_pcaps.json"

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_dirs():
    for d in [PCAP_DIR, CLEANED_DIR, MODELS_DIR]:
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)

def load_expected_columns():
    if not COLUMNS_PKL.exists():
        print(f"[{now()}] FATAL ERROR: Could not find {COLUMNS_PKL}.")
        print(f"[{now()}] Please run your training script first to generate the model signature.")
        sys.exit(1)
    try:
        # Load the columns from the training script
        columns = joblib.load(COLUMNS_PKL)
        # We only want the features, not the target labels!
        columns = [c for c in columns if c not in ["label1", "label2"]]
        print(f"[{now()}] Successfully loaded {len(columns)} expected features from {COLUMNS_PKL.name}")
        return columns
    except Exception as e:
        print(f"[{now()}] FATAL ERROR: Failed to load columns pickle: {e}")
        sys.exit(1)

def load_processed():
    if PROCESSED_DB.exists():
        text = PROCESSED_DB.read_text().strip()
        if not text:
            return set()
        try:
            return set(json.loads(text))
        except Exception as e:
            print(f"[{now()}] Warning: Could not read processed DB ({e}). Starting fresh.")
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
        if start:
            if nowdt < start + timedelta(seconds=SNIFFER_DURATION + SAFETY_MARGIN):
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
        print(f"[{now()}] Failed to read {path.name}: {e}")
        return pd.DataFrame(columns=expected_columns)
    
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
            flows[flow_key] = {
                "pkts": [],
                "anchor_src": src_ip,
                "proto": proto
            }
        flows[flow_key]["pkts"].append(pkt)

    flow_records = []
    
    for flow_key, data in flows.items():
        pkts = data["pkts"]
        anchor_src = data["anchor_src"]
        proto_num = float(data["proto"])
        
        times = [float(p.time) for p in pkts]
        sizes = [len(p) for p in pkts]
        ip_lengths = [len(p[IPv6]) if IPv6 in p else p[IP].len for p in pkts]
        header_lengths = [40 if IPv6 in p else p[IP].ihl * 4 for p in pkts]
        payload_lengths = [sizes[i] - header_lengths[i] for i in range(len(pkts))]
        
        ip_flags = []
        frag_count = 0
        for p in pkts:
            if IP in p:
                try: 
                    flag_val = int(p[IP].flags)
                    ip_flags.append(float(flag_val))
                    # MF flag (0x1) or non-zero frag offset indicates fragmentation
                    if p[IP].frag > 0 or (flag_val & 0x1):
                        frag_count += 1
                except: ip_flags.append(0.0)
            else:
                ip_flags.append(0.0)
                
        time_deltas = [times[i] - times[i-1] for i in range(1, len(times))] if len(times) > 1 else [0.0]
        interval_packets = float(np.mean(time_deltas))
        
        syn_c = ack_c = fin_c = psh_c = rst_c = urg_c = 0
        tcp_flag_values = []
        
        for p in pkts:
            if TCP in p:
                flags = p[TCP].flags
                syn_c += 1 if 'S' in flags else 0
                ack_c += 1 if 'A' in flags else 0
                fin_c += 1 if 'F' in flags else 0
                psh_c += 1 if 'P' in flags else 0
                rst_c += 1 if 'R' in flags else 0
                urg_c += 1 if 'U' in flags else 0
                tcp_flag_values.append(float(int(flags)))
            else:
                tcp_flag_values.append(0.0)

        src_pkts_count = 0
        dst_pkts_count = 0
        for p in pkts:
            ip_l = p[IPv6] if IPv6 in p else p[IP]
            if ip_l.src == anchor_src:
                src_pkts_count += 1
            else:
                dst_pkts_count += 1

        # Build exactly the minimal feature dictionary
        record = {
            'network_fragmented-packets': float(frag_count),
            'network_header-length_avg': float(np.mean(header_lengths)),
            'network_header-length_max': float(np.max(header_lengths)),
            'network_header-length_min': float(np.min(header_lengths)),
            'network_header-length_std_deviation': safe_std(header_lengths),
            
            'network_interval-packets': interval_packets,
            
            'network_ip-flags_avg': float(np.mean(ip_flags)),
            'network_ip-flags_max': float(np.max(ip_flags)),
            'network_ip-flags_min': float(np.min(ip_flags)),
            'network_ip-flags_std_deviation': safe_std(ip_flags),
            
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
            
            # Use the actual protocol integer (e.g., 6 for TCP, 17 for UDP)
            'network_protocols_all': proto_num,
            'network_protocols_dst': proto_num,
            'network_protocols_src': proto_num,
            
            'network_tcp-flags-ack_count': float(ack_c),
            'network_tcp-flags-fin_count': float(fin_c),
            'network_tcp-flags-psh_count': float(psh_c),
            'network_tcp-flags-rst_count': float(rst_c),
            'network_tcp-flags-syn_count': float(syn_c),
            'network_tcp-flags-urg_count': float(urg_c),
            
            'network_tcp-flags_avg': float(np.mean(tcp_flag_values)),
            'network_tcp-flags_max': float(np.max(tcp_flag_values)),
            'network_tcp-flags_min': float(np.min(tcp_flag_values)),
            'network_tcp-flags_std_deviation': safe_std(tcp_flag_values),
            
            'network_time-delta_avg': float(np.mean(time_deltas)),
            'network_time-delta_max': float(np.max(time_deltas)),
            'network_time-delta_min': float(np.min(time_deltas)),
            'network_time-delta_std_deviation': safe_std(time_deltas)
        }
        flow_records.append(record)

    if not flow_records:
        return pd.DataFrame(columns=expected_columns)

    df = pd.DataFrame(flow_records)
    
    # Clean infinities and NaNs mathematically
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0.0, inplace=True)
    
    # Enforce strict column presence and ordering based on the .pkl
    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0.0
            
    df = df[expected_columns]
    
    return df

def main():
    ensure_dirs()
    expected_columns = load_expected_columns()
    processed = load_processed()
    print(f"[{now()}] Unified Data Processor listening on {PCAP_DIR}...")

    try:
        while True:
            files = stable_ready_files(processed)

            for p in files:
                print(f"[{now()}] Processing {p.name}")
                df = process_pcap(p, expected_columns)

                out_name = p.stem + ".cleaned.csv"
                out_path = CLEANED_DIR / out_name

                df.to_csv(out_path, index=False)
                print(f"[{now()}] Wrote highly-optimized features to {out_path.name}")

                processed.add(p.name)
                save_processed(processed)

            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print(f"\n[{now()}] Interrupted by user. Saving state and exiting.")
        save_processed(processed)

if __name__ == "__main__":
    main()