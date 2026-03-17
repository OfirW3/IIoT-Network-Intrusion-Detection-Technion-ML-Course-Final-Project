#!/usr/bin/env python3

import time
import json
import re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict

import numpy as np
import pandas as pd

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Ether

# CONFIG
PCAP_DIR = Path("../data/pcaps")
OUT_DIR = Path("../data/raw_csvs")

POLL_INTERVAL = 5
STABLE_WAIT = 1
SNIFFER_DURATION = 20
SAFETY_MARGIN = 2

PROCESSED_DB = OUT_DIR / "processed_pcaps.json"


COLUMNS = [
"device_mac","device_name","label","label1","label2","label3","label4","label_full",
"log_data-ranges_avg","log_data-ranges_max","log_data-ranges_min","log_data-ranges_std_deviation",
"log_data-types","log_data-types_count","log_interval-messages","log_messages_count",
"network_fragmentation-score","network_fragmented-packets",
"network_header-length_avg","network_header-length_max","network_header-length_min","network_header-length_std_deviation",
"network_interval-packets",
"network_ip-flags_avg","network_ip-flags_max","network_ip-flags_min","network_ip-flags_std_deviation",
"network_ip-length_avg","network_ip-length_max","network_ip-length_min","network_ip-length_std_deviation",
"network_ips_all","network_ips_all_count","network_ips_dst","network_ips_dst_count","network_ips_src","network_ips_src_count",
"network_macs_all","network_macs_all_count","network_macs_dst","network_macs_dst_count","network_macs_src","network_macs_src_count",
"network_mss_avg","network_mss_max","network_mss_min","network_mss_std_deviation",
"network_packet-size_avg","network_packet-size_max","network_packet-size_min","network_packet-size_std_deviation",
"network_packets_all_count","network_packets_dst_count","network_packets_src_count",
"network_payload-length_avg","network_payload-length_max","network_payload-length_min","network_payload-length_std_deviation",
"network_ports_all","network_ports_all_count","network_ports_dst","network_ports_dst_count","network_ports_src","network_ports_src_count",
"network_protocols_all","network_protocols_all_count","network_protocols_dst","network_protocols_dst_count","network_protocols_src","network_protocols_src_count",
"network_tcp-flags-ack_count","network_tcp-flags-fin_count","network_tcp-flags-psh_count","network_tcp-flags-rst_count",
"network_tcp-flags-syn_count","network_tcp-flags-urg_count",
"network_tcp-flags_avg","network_tcp-flags_max","network_tcp-flags_min","network_tcp-flags_std_deviation",
"network_time-delta_avg","network_time-delta_max","network_time-delta_min","network_time-delta_std_deviation",
"network_ttl_avg","network_ttl_max","network_ttl_min","network_ttl_std_deviation",
"network_window-size_avg","network_window-size_max","network_window-size_min","network_window-size_std_deviation",
"timestamp","timestamp_end","timestamp_start"
]


def now():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def ensure_dirs():
    if not PCAP_DIR.exists():
        raise RuntimeError("Missing data/pcaps directory")
    if not OUT_DIR.exists():
        raise RuntimeError("Missing data/raw_csvs directory")


def load_processed():
    if PROCESSED_DB.exists():
        text = PROCESSED_DB.read_text().strip()
        if not text:  # If the file exists but is completely empty
            return set()
        try:
            return set(json.loads(text))
        except Exception as e:
            print(f"Warning: Could not read processed DB ({e}). Starting fresh.")
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


def safe_stats(values):
    if not values:
        return (0,0,0,0)
    a = np.array(values)
    return float(a.mean()), float(a.max()), float(a.min()), float(a.std())


def count_tcp_flag_bits(flag_ints):
    # returns dict with counts for the main flags (ACK, FIN, PSH, RST, SYN, URG)
    ack = fin = psh = rst = syn = urg = 0
    for v in flag_ints:
        try:
            v = int(v)
        except:
            v = 0
        if v & 0x10:  # ACK
            ack += 1
        if v & 0x01:  # FIN
            fin += 1
        if v & 0x08:  # PSH
            psh += 1
        if v & 0x04:  # RST
            rst += 1
        if v & 0x02:  # SYN
            syn += 1
        if v & 0x20:  # URG
            urg += 1
    return {"ack":ack, "fin":fin, "psh":psh, "rst":rst, "syn":syn, "urg":urg}


def process_pcap(path):
    flows = defaultdict(lambda: {
        "times": [],
        "time_deltas": [],
        "pkt_len": [],
        "payload": [],
        "ttl": [],
        "ip_len": [],
        "flags": [],
        "window": [],
        "mss": [],
        "hdr_len": [],
        "tcp_flags": [],
        
        "fragmented_count": 0,
        "pkts_src": 0,
        "pkts_dst": 0,
        
        "ips_all": set(),
        "ips_src": set(),
        "ips_dst": set(),
        
        "ports_all": set(),
        "ports_src": set(),
        "ports_dst": set(),
        
        "macs_all": set(),
        "macs_src": set(),
        "macs_dst": set(),
        
        "protos_all": set(),
        "protos_src": set(),
        "protos_dst": set(),
        
        # Used to anchor direction (IP + Port allows loopback testing)
        "flow_src_ip": None,
        "flow_src_port": None
    })

    reader = PcapReader(str(path))

    for pkt in reader:
        try:
            # IP/IPv6 Parsing
            if IP in pkt:
                ip = pkt[IP]
                src, dst, proto = ip.src, ip.dst, ip.proto
                ttl = getattr(ip, "ttl", 0)
                iplen = getattr(ip, "len", None) or len(pkt)
                try: flags = int(ip.flags)
                except: flags = 0
                fragmented = (getattr(ip, "frag", 0) != 0) or (flags & 0x1 != 0)
            elif IPv6 in pkt:
                ip = pkt[IPv6]
                src, dst, proto = ip.src, ip.dst, ip.nh
                ttl = getattr(ip, "hlim", 0)
                iplen = len(pkt)
                flags = 0
                fragmented = False
            else:
                continue

            # Transport Parsing
            sport = dport = window = tcpflags = 0
            if TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                proto_name = "TCP"
                window = getattr(pkt[TCP], "window", 0)
                try: tcpflags = int(pkt[TCP].flags)
                except: tcpflags = 0
            elif UDP in pkt:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
                proto_name = "UDP"
            else:
                proto_name = "OTHER"

            key = tuple(sorted([(src, sport), (dst, dport)])) + (proto,)
            f = flows[key]

            # Anchor Direction (crucial for loopback/localhost testing)
            if f["flow_src_ip"] is None:
                f["flow_src_ip"] = src
                f["flow_src_port"] = sport
                
            is_src = (src == f["flow_src_ip"] and sport == f["flow_src_port"])

            # Time Processing (calculates deltas!)
            try: t_val = float(pkt.time)
            except: t_val = time.time()
            
            if f["times"]:
                delta = t_val - f["times"][-1]
                f["time_deltas"].append(max(0.0, delta))
            f["times"].append(t_val)

            # Feature Appending
            f["pkt_len"].append(int(len(pkt)))
            try: f["payload"].append(int(len(pkt.payload)))
            except: f["payload"].append(0)
            f["ttl"].append(int(ttl))
            f["ip_len"].append(int(iplen))
            f["flags"].append(int(flags))
            f["window"].append(int(window))
            f["tcp_flags"].append(int(tcpflags))

            try:
                hdr_len_est = int(len(pkt) - len(pkt.payload))
                f["hdr_len"].append(max(0, hdr_len_est))
            except:
                f["hdr_len"].append(0)

            if fragmented:
                f["fragmented_count"] += 1

            # TCP Options parsing (MSS)
            if TCP in pkt and getattr(pkt[TCP], "options", None):
                for o in pkt[TCP].options:
                    if isinstance(o, tuple) and len(o) >= 2 and o[0] == 'MSS':
                        try: f["mss"].append(int(o[1]))
                        except: pass

            # Directional Sets & Counts
            if is_src:
                f["pkts_src"] += 1
                f["ips_src"].add(src)
                f["ports_src"].add(sport)
                f["protos_src"].add(proto_name)
            else:
                f["pkts_dst"] += 1
                f["ips_dst"].add(src) 
                f["ports_dst"].add(sport)
                f["protos_dst"].add(proto_name)

            f["ips_all"].update([src, dst])
            f["ports_all"].update([sport, dport])
            f["protos_all"].add(proto_name)

            if Ether in pkt:
                mac_src, mac_dst = pkt[Ether].src, pkt[Ether].dst
                f["macs_all"].update([mac_src, mac_dst])
                if is_src:
                    f["macs_src"].add(mac_src)
                    f["macs_dst"].add(mac_dst)
                else:
                    f["macs_dst"].add(mac_src)
                    f["macs_src"].add(mac_dst)

        except Exception:
            continue

    reader.close()

    rows = []
    for key, data in flows.items():
        if not data["times"]:
            continue

        t0, t1 = float(min(data["times"])), float(max(data["times"]))
        totals = len(data["pkt_len"])

        pkt_avg, pkt_max, pkt_min, pkt_std = safe_stats(data["pkt_len"])
        pay_avg, pay_max, pay_min, pay_std = safe_stats(data["payload"])
        ttl_avg, ttl_max, ttl_min, ttl_std = safe_stats(data["ttl"])
        ip_avg, ip_max, ip_min, ip_std = safe_stats(data["ip_len"])
        win_avg, win_max, win_min, win_std = safe_stats(data["window"])
        hdr_avg, hdr_max, hdr_min, hdr_std = safe_stats(data["hdr_len"])
        mss_avg, mss_max, mss_min, mss_std = safe_stats(data["mss"])
        flags_avg, flags_max, flags_min, flags_std = safe_stats(data["flags"])
        tcpflags_avg, tcpflags_max, tcpflags_min, tcpflags_std = safe_stats(data["tcp_flags"])
        td_avg, td_max, td_min, td_std = safe_stats(data["time_deltas"])

        frag_count = data["fragmented_count"]
        frag_score = float(frag_count) / totals if totals > 0 else 0.0

        tcp_flag_counts = count_tcp_flag_bits(data["tcp_flags"])

        row = {c: "" for c in COLUMNS}

        # Original features
        row["device_mac"] = ";".join(sorted(data["macs_all"])) if data["macs_all"] else ""
        row["network_packet-size_avg"], row["network_packet-size_max"], row["network_packet-size_min"], row["network_packet-size_std_deviation"] = pkt_avg, pkt_max, pkt_min, pkt_std
        row["network_payload-length_avg"], row["network_payload-length_max"], row["network_payload-length_min"], row["network_payload-length_std_deviation"] = pay_avg, pay_max, pay_min, pay_std
        row["network_ttl_avg"], row["network_ttl_max"], row["network_ttl_min"], row["network_ttl_std_deviation"] = ttl_avg, ttl_max, ttl_min, ttl_std
        row["network_ip-length_avg"], row["network_ip-length_max"], row["network_ip-length_min"], row["network_ip-length_std_deviation"] = ip_avg, ip_max, ip_min, ip_std
        row["network_header-length_avg"], row["network_header-length_max"], row["network_header-length_min"], row["network_header-length_std_deviation"] = hdr_avg, hdr_max, hdr_min, hdr_std
        row["network_window-size_avg"], row["network_window-size_max"], row["network_window-size_min"], row["network_window-size_std_deviation"] = win_avg, win_max, win_min, win_std
        
        row["network_mss_avg"], row["network_mss_max"], row["network_mss_min"], row["network_mss_std_deviation"] = mss_avg, mss_max, mss_min, mss_std
        row["network_fragmentation-score"] = frag_score
        row["network_fragmented-packets"] = frag_count
        row["network_ip-flags_avg"], row["network_ip-flags_max"], row["network_ip-flags_min"], row["network_ip-flags_std_deviation"] = flags_avg, flags_max, flags_min, flags_std
        
        row["network_tcp-flags-ack_count"] = tcp_flag_counts["ack"]
        row["network_tcp-flags-fin_count"] = tcp_flag_counts["fin"]
        row["network_tcp-flags-psh_count"] = tcp_flag_counts["psh"]
        row["network_tcp-flags-rst_count"] = tcp_flag_counts["rst"]
        row["network_tcp-flags-syn_count"] = tcp_flag_counts["syn"]
        row["network_tcp-flags-urg_count"] = tcp_flag_counts["urg"]
        row["network_tcp-flags_avg"], row["network_tcp-flags_max"], row["network_tcp-flags_min"], row["network_tcp-flags_std_deviation"] = tcpflags_avg, tcpflags_max, tcpflags_min, tcpflags_std

        row["timestamp"], row["timestamp_start"], row["timestamp_end"] = datetime.fromtimestamp(t0, timezone.utc).isoformat(), datetime.fromtimestamp(t0, timezone.utc).isoformat(), datetime.fromtimestamp(t1, timezone.utc).isoformat()

        # === THE NEWLY FIXED MISSING FEATURES ===
        row["network_packets_all_count"] = totals
        row["network_packets_src_count"] = data["pkts_src"]
        row["network_packets_dst_count"] = data["pkts_dst"]

        row["network_time-delta_avg"], row["network_time-delta_max"], row["network_time-delta_min"], row["network_time-delta_std_deviation"] = td_avg, td_max, td_min, td_std
        row["network_interval-packets"] = (t1 - t0) / totals if totals > 1 else 0.0

        row["network_ips_all"] = ";".join(sorted(data["ips_all"]))
        row["network_ips_all_count"] = len(data["ips_all"])
        row["network_ips_src"] = ";".join(sorted(data["ips_src"]))
        row["network_ips_src_count"] = len(data["ips_src"])
        row["network_ips_dst"] = ";".join(sorted(data["ips_dst"]))
        row["network_ips_dst_count"] = len(data["ips_dst"])

        row["network_ports_all"] = ";".join(map(str, sorted(data["ports_all"])))
        row["network_ports_all_count"] = len(data["ports_all"])
        row["network_ports_src"] = ";".join(map(str, sorted(data["ports_src"])))
        row["network_ports_src_count"] = len(data["ports_src"])
        row["network_ports_dst"] = ";".join(map(str, sorted(data["ports_dst"])))
        row["network_ports_dst_count"] = len(data["ports_dst"])

        row["network_protocols_all"] = ";".join(sorted(data["protos_all"]))
        row["network_protocols_all_count"] = len(data["protos_all"])
        row["network_protocols_src"] = ";".join(sorted(data["protos_src"]))
        row["network_protocols_src_count"] = len(data["protos_src"])
        row["network_protocols_dst"] = ";".join(sorted(data["protos_dst"]))
        row["network_protocols_dst_count"] = len(data["protos_dst"])
        
        row["network_macs_all"] = ";".join(sorted(data["macs_all"]))
        row["network_macs_all_count"] = len(data["macs_all"])
        row["network_macs_src"] = ";".join(sorted(data["macs_src"]))
        row["network_macs_src_count"] = len(data["macs_src"])
        row["network_macs_dst"] = ";".join(sorted(data["macs_dst"]))
        row["network_macs_dst_count"] = len(data["macs_dst"])

        rows.append(row)

    return rows


def stable_ready_files(processed):

    ready=[]
    nowdt=datetime.now()

    for f in PCAP_DIR.glob("*.pcap"):

        if f.name in processed:
            continue

        start=parse_time_from_filename(f.name)

        if start:
            if nowdt < start + timedelta(seconds=SNIFFER_DURATION+SAFETY_MARGIN):
                continue

        s1=f.stat().st_size
        time.sleep(STABLE_WAIT)
        s2=f.stat().st_size

        if s1!=s2:
            continue

        ready.append(f)

    return ready


def main():

    ensure_dirs()

    processed=load_processed()

    print(f"{now()} watching {PCAP_DIR}")

    try:
        while True:

            files=stable_ready_files(processed)

            for p in files:

                print(f"{now()} processing {p.name}")

                rows=process_pcap(p)

                out=OUT_DIR/(p.stem+".raw.csv")

                df=pd.DataFrame(rows,columns=COLUMNS)

                # Post-process: for numeric-like columns, replace empty string/NaN with 0.
                for col in df.columns:
                    non_blank = df[df[col] != ""][col]
                    if non_blank.empty:
                        df[col] = 0
                        continue
                    # try to coerce the non-empty subset to numeric
                    try:
                        pd.to_numeric(non_blank)
                        # column appears numeric -> replace blanks with 0 and coerce whole column to numeric
                        df[col] = df[col].replace("", 0)  # <--- Removed .loc[:, ]
                        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)  # <--- Removed .loc[:, ]
                    except Exception:
                        # non-numeric textual column - leave as-is
                        pass

                df.to_csv(out,index=False)

                print(f"{now()} wrote {out}")

                processed.add(p.name)
                save_processed(processed)

            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print(f"\n{now()} interrupted by user (KeyboardInterrupt). Saving state and exiting.")
        save_processed(processed)


if __name__=="__main__":
    main()