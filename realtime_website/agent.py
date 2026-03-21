import time
import subprocess
from pymongo import MongoClient
import sys
import hashlib
import requests
import os
import threading
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime, timezone

# --- CONFIGURATION ---
SIEM_DB_URL = "mongodb://172.17.0.1:27017/"
DEFAULT_PATHS = ["/etc/nginx", "/var/www/html", "/root", "/var/log/nginx"] 
CHECK_INTERVAL = 10 
BACKEND_URL = "http://172.17.0.1:8000/api/alerts"
CONFIG_URL = "http://172.17.0.1:8000/api/config"
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

sessions = {}

def process_packet(packet, logs_col):
    if packet.haslayer(IP):
        # FIXED: Use timezone-aware datetime and correct class reference
        now = datetime.now(timezone.utc)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_str = PROTO_MAP.get(packet[IP].proto, "other")
        
        state = "INT"
        sbytes, dbytes = 0, 0
        sttl, dttl = 0, 0
        stcpb, dtcpb = 0, 0
        synack, ackdat = 0.0, 0.0
        
        sport = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
        dport = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)
        
        flow_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
        if flow_key not in sessions:
            sessions[flow_key] = {'start_time': now, 'last_packet_time': now, 'syn_time': None, 'synack_time': None}
        session = sessions[flow_key]

        is_request = dport in [80, 443, 8080] or proto_str == "udp"

        if is_request:
            sbytes = len(packet)
            sttl = packet[IP].ttl
        else:
            dbytes = len(packet)
            dttl = packet[IP].ttl

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'S' in flags and 'A' not in flags: state = "REQ"
            elif 'S' in flags and 'A' in flags: state = "CON"
            elif 'F' in flags: state = "FIN"
            elif 'R' in flags: state = "RST"
            elif 'A' in flags: state = "CON"

            if is_request: stcpb = packet[TCP].seq
            else: dtcpb = packet[TCP].seq

            if 'S' in flags and 'A' not in flags:
                session['syn_time'] = now
            elif 'S' in flags and 'A' in flags:
                if session['syn_time']:
                    synack = (now - session['syn_time']).total_seconds()
                    session['synack_time'] = now
            elif 'A' in flags and session['synack_time']:
                ackdat = (now - session['synack_time']).total_seconds()

        time_diff = (now - session['last_packet_time']).total_seconds()
        sinpkt = time_diff if is_request else 0
        dinpkt = time_diff if not is_request else 0
        session['last_packet_time'] = now

        network_log = {
            "source": "network-interface",
            "timestamp": now,
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": sport, "dst_port": dport, # FIXED: Added ports to dictionary
            "proto": proto_str,
            "state": state,
            "service": SERVICE_MAP.get(dport if is_request else sport, "-"),
            "sbytes": sbytes, "dbytes": dbytes,
            "sttl": sttl, "dttl": dttl,
            "stcpb": stcpb, "dtcpb": dtcpb,
            "sinpkt": sinpkt, "dinpkt": dinpkt,
            "synack": synack, "ackdat": ackdat,
            "is_sm_ips_ports": 1 if (src_ip == dst_ip and sport == dport) else 0,
            "processed": False
        }

        # FIXED: Ensure we don't log traffic to our own database (infinite loop prevention)
        if state in ["REQ", "FIN", "RST", "INT", "CON"]:
            if network_log["dst_port"] != 27017 and network_log["src_port"] != 27017:
                try:
                    logs_col.insert_one(network_log)
                except Exception: pass

def start_network_sniffer(client):
    db = client.siem_db
    logs_col = db.network_logs
    print("[*] Network Sniffer active. Capturing traffic...")
    sniff(prn=lambda pkt: process_packet(pkt, logs_col), store=0)

def get_latest_watch_paths():
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

    while True:
        time.sleep(CHECK_INTERVAL)
        watch_list = get_latest_watch_paths()
        files_found_on_disk = set()

        for path in watch_list:
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    files_found_on_disk.add(full_path)
                    current_hash = calculate_sha256(full_path)
                    if not current_hash: continue

                    if full_path not in baseline:
                        alert = {"type": "FIM_NEW_FILE", "file": full_path, "severity": "medium"}
                        send_fim_alert(alert)
                        alerts_col.insert_one({**alert, "time": time.ctime(), "hash": current_hash})
                        baseline[full_path] = current_hash
                        hashes_col.update_one({"filepath": full_path}, {"$set": {"hash": current_hash}}, upsert=True)

                    elif current_hash != baseline[full_path]:
                        alert = {"type": "FIM_MODIFICATION", "file": full_path, "severity": "high"}
                        send_fim_alert(alert)
                        alerts_col.insert_one({
                            **alert, "time": time.ctime(), 
                            "old_hash": baseline[full_path], "new_hash": current_hash
                        })
                        baseline[full_path] = current_hash
                        hashes_col.update_one({"filepath": full_path}, {"$set": {"hash": current_hash}})

        baseline_paths = list(baseline.keys())
        for path in baseline_paths:
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
        requests.post(BACKEND_URL, json=data, timeout=15)
    except Exception as e:
        print(f"[!] Failed to ship alert: {e}")

def start_log_shipper(client):
    db = client.siem_db
    logs_col = db.raw_logs
    print("[*] Log Shipper active. Tailing Ecommerce logs...")
    proc = subprocess.Popen(
        ['tail', '-F', '/var/log/nginx/access.log'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

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

    print("[*] Starting FIM Monitor Thread...")
    threading.Thread(target=run_fim_monitor, args=(client,), daemon=True).start()

    print("[*] Starting Network Sniffer Thread...")
    threading.Thread(target=start_network_sniffer, args=(client,), daemon=True).start()

    try:
        start_log_shipper(client)
    except KeyboardInterrupt:
        print("\n[!] Agent shutting down...")

if __name__ == "__main__":
    main()
