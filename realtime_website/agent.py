import time
import subprocess
from pymongo import MongoClient
import sys
import hashlib
import requests
import os
import threading
from scapy.all import sniff, IP, TCP
import datetime

# --- CONFIGURATION ---
SIEM_DB_URL = "mongodb://172.17.0.1:27017/"
# These are used only if the Backend API is unreachable
DEFAULT_PATHS = ["/etc/nginx", "/var/www/html", "/root", "/var/log/nginx"] 
CHECK_INTERVAL = 10 
BACKEND_URL = "http://172.17.0.1:8000/api/alerts"
CONFIG_URL = "http://172.17.0.1:8000/api/config" # The new endpoint we added to main.py
SERVICE_MAP = {80: "http", 443: "http", 53: "dns", 21: "ftp", 22: "ssh"}
PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        if not os.path.isfile(filepath): return None
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None

# global session tracker to calculate timings and aggregates
# Format: {(src, sport, dst, dport): {last_time: x, syn_time: y, ...}}
sessions = {}

def process_packet(packet, logs_col):
    if packet.haslayer(IP):
        now = datetime.datetime.utcnow()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        proto_str = PROTO_MAP.get(proto_num, "other")
        
        # Initialize default values
        state = "INT"  # Default for UDP
        sbytes, dbytes = 0, 0
        sttl, dttl = 0, 0
        stcpb, dtcpb = 0, 0
        
        # --- 1. Identify Flow & Direction ---
        sport = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
        dport = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)
        
        flow_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
        if flow_key not in sessions:
            sessions[flow_key] = {
                'start_time': now, 'last_packet_time': now,
                'syn_time': None, 'synack_time': None,
                'sbytes': 0, 'dbytes': 0
            }
        session = sessions[flow_key]

        # Determine if this is source -> destination (request) or vice versa
        is_request = dport in [80, 443, 8080] or proto_str == "udp"

        # --- 2. State & TCP Specific Logic ---
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            # Mapping Logic
            if 'S' in flags and 'A' not in flags: 
                state = "REQ"  # Connection Request
            elif 'S' in flags and 'A' in flags: 
                state = "CON"  # Connection Established (SYN-ACK)
            elif 'F' in flags: 
                state = "FIN"  # Finished (This fixes your "FA" issue)
            elif 'R' in flags: 
                state = "RST"  # Reset
            elif 'A' in flags: 
                state = "CON"  # Connected / Acknowledge    

            if is_request:
                sbytes = len(packet)
                sttl = packet[IP].ttl
                stcpb = packet[TCP].seq
            else:
                dbytes = len(packet)
                dttl = packet[IP].ttl
                dtcpb = packet[TCP].seq

            # Handshake Timings
            if 'S' in flags and 'A' not in flags:
                session['syn_time'] = now
            elif 'S' in flags and 'A' in flags:
                if session['syn_time']:
                    synack = (now - session['syn_time']).total_seconds()
                    session['synack_time'] = now
            elif 'A' in flags and session['synack_time']:
                ackdat = (now - session['synack_time']).total_seconds()

        # --- 3. Inter-packet Times (sinpkt / dinpkt) ---
        time_diff = (now - session['last_packet_time']).total_seconds()
        sinpkt = time_diff if is_request else 0
        dinpkt = time_diff if not is_request else 0
        session['last_packet_time'] = now

        # --- 4. Final Log Construction (Dataset Schema) ---
        network_log = {
            "source": "network-interface",
            "timestamp": now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto_str,         # Dataset uses strings: 'tcp', 'udp'
            "state": state,             # Dataset uses: 'REQ', 'CON', 'FIN', 'INT'
            "service": SERVICE_MAP.get(dport if is_request else sport, "-"),
            "sbytes": sbytes,           # Source bytes
            "dbytes": dbytes,           # Destination bytes
            "sttl": sttl,               # Source TTL
            "dttl": dttl,               # Destination TTL
            "stcpb": stcpb,             # Source TCP Base Sequence
            "dtcpb": dtcpb,             # Destination TCP Base Sequence
            "sinpkt": sinpkt,           # Source inter-packet time
            "dinpkt": dinpkt,           # Destination inter-packet time
            "synack": locals().get('synack', 0),
            "ackdat": locals().get('ackdat', 0),
            "is_sm_ips_ports": 1 if (src_ip == dst_ip and sport == dport) else 0,
            "processed": False
        }

        # --- 5. Filtering and Shipping ---
        # We only ship when a state change occurs or for UDP starts to save DB space
        if state in ["REQ", "FIN", "RST", "INT"] and network_log["src_ip"] != "172.17.0.1":
            try:
                logs_col.insert_one(network_log)
            except Exception:
                pass

def start_network_sniffer(client):
    db = client.siem_db
    logs_col = db.network_logs # New collection
    print("[*] Network Sniffer active. Capturing traffic...")
    
    # Sniff packets (filter='tcp' or leave empty for all traffic)
    sniff(prn=lambda pkt: process_packet(pkt, logs_col), store=0)

def get_latest_watch_paths():
    """Fetches the current monitoring list from the Backend API."""
    try:
        response = requests.get(CONFIG_URL, timeout=2)
        if response.status_code == 200:
            return response.json().get("paths", DEFAULT_PATHS)
    except Exception as e:
        print(f"[!] Config Sync Failed: {e}. Using defaults.")
    return DEFAULT_PATHS

def run_fim_monitor(client):
    fim_db = client.fim_integrity
    hashes_col = fim_db.file_baselines
    alerts_col = fim_db.fim_alerts

    # --- STEP 1: INITIAL BASELINE ---
    print("[*] FIM: Syncing with Backend Configuration...")
    baseline = {}
    watch_list = get_latest_watch_paths()
    
    for path in watch_list:
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                file_hash = calculate_sha256(full_path)
                if file_hash:
                    baseline[full_path] = file_hash
                    hashes_col.update_one(
                        {"filepath": full_path},
                        {"$set": {"hash": file_hash, "last_check": time.time()}},
                        upsert=True
                    )
    print(f"[+] FIM: Initial Baseline established for {len(baseline)} files.")

    # --- STEP 2: CONTINUOUS DYNAMIC LOOP ---
    while True:
        time.sleep(CHECK_INTERVAL)
        
        # Sync paths every loop so the UI can add new folders in real-time
        watch_list = get_latest_watch_paths()
        files_found_on_disk = set()

        for path in watch_list:
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    files_found_on_disk.add(full_path)
                    
                    current_hash = calculate_sha256(full_path)
                    if not current_hash: continue

                    # DETECT NEW FILES (Automatically handles newly added directories)
                    if full_path not in baseline:
                        alert = {"type": "FIM_NEW_FILE", "file": full_path, "severity": "medium"}
                        send_fim_alert(alert)
                        alerts_col.insert_one({**alert, "time": time.ctime(), "hash": current_hash})
                        baseline[full_path] = current_hash
                        hashes_col.update_one({"filepath": full_path}, {"$set": {"hash": current_hash}}, upsert=True)

                    # DETECT MODIFICATIONS
                    elif current_hash != baseline[full_path]:
                        alert = {"type": "FIM_MODIFICATION", "file": full_path, "severity": "high"}
                        send_fim_alert(alert)
                        alerts_col.insert_one({
                            **alert, "time": time.ctime(), 
                            "old_hash": baseline[full_path], "new_hash": current_hash
                        })
                        baseline[full_path] = current_hash
                        hashes_col.update_one({"filepath": full_path}, {"$set": {"hash": current_hash}})

        # DETECT DELETIONS
        baseline_paths = list(baseline.keys())
        for path in baseline_paths:
            # If a file is missing AND its parent directory is still in our watch list
            if path not in files_found_on_disk:
                if any(path.startswith(watched) for watched in watch_list):
                    alert = {"type": "FIM_DELETION", "file": path, "severity": "critical"}
                    print(f"[!!] DELETION DETECTED: {path}")
                    send_fim_alert(alert)
                    alerts_col.insert_one({**alert, "time": time.ctime()})
                    
                    del baseline[path]
                    hashes_col.delete_one({"filepath": path})

def send_fim_alert(data):
    try:
        requests.post(BACKEND_URL, json=data, timeout=5)
    except Exception as e:
        print(f"[!] Failed to ship alert: {e}")

def start_log_shipper(client):
    """
    Main thread logic for tailing Nginx logs.
    Ships raw logs to the 'siem_db' for analysis.
    """
    # --- STEP 1: Setup Log Collection ---
    db = client.siem_db
    logs_col = db.raw_logs

    # --- STEP 2: Start Tailing access.log ---
    print("[*] Log Shipper active. Tailing Ecommerce logs...")
    proc = subprocess.Popen(
        ['tail', '-F', '/var/log/nginx/access.log'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # --- STEP 3: Ship Logs to Mongo ---
    while True:
        line = proc.stdout.readline()
        if line:
            clean_line = line.strip()
            log_entry = {
                "source": "ecommerce-production-site",
                "timestamp": time.time(),
                "raw_message": clean_line,
                "processed": False 
            }
            try:
                logs_col.insert_one(log_entry)
            except Exception as e:
                print(f"[!] Failed to ship log: {e}")
        else:
            time.sleep(0.1)


def main():
    # Connect to MongoDB
    client = None
    while True:
        try:
            print(f"[*] Connecting to SIEM MongoDB at {SIEM_DB_URL}...")
            client = MongoClient(SIEM_DB_URL, serverSelectionTimeoutMS=2000)
            client.admin.command('ping')
            print("[+] Successfully connected!")
            break
        except Exception as e:
            print(f"[!] Connection failed: {e}. Retrying...")
            time.sleep(5)

    # --- THREAD 1: FIM (File Integrity) ---
    print("[*] Starting FIM Monitor Thread...")
    fim_thread = threading.Thread(target=run_fim_monitor, args=(client,), daemon=True)
    fim_thread.start()

    # --- THREAD 2: Network Sniffing ---
    print("[*] Starting Network Sniffer Thread...")
    net_thread = threading.Thread(target=start_network_sniffer, args=(client,), daemon=True)
    net_thread.start()

    # --- THREAD 3 (Main Thread): Log Shipping ---
    # We keep this in the main thread so the script stays alive
    try:
        start_log_shipper(client)
    except KeyboardInterrupt:
        print("\n[!] Agent shutting down...")

if __name__ == "__main__":
    main()
