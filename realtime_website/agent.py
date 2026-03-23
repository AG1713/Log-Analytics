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
import getpass


# --- CONFIGURATION ---
SIEM_DB_URL = "mongodb://172.17.0.1:27017/"
DEFAULT_PATHS = ["/etc/nginx", "/var/www/html", "/root", "/var/log/nginx"] 
CHECK_INTERVAL = 10 
BACKEND_URL = "http://172.17.0.1:8000/api/alerts"
CONFIG_URL = "http://172.17.0.1:8000/api/config"
SERVICE_MAP = {80: "http", 443: "http", 53: "dns", 21: "ftp", 22: "ssh"}
PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}

def check_permissions():
    # Check if we are root
    if os.geteuid() == 0:
        return True
    
    # If not root, check if we have the specific capability to sniff
    # (This handles your Docker 'setcap' scenario)
    try:
        # We try to open a dummy socket to see if the OS allows it
        from scapy.all import conf
        conf.L2socket
        return True
    except Exception:
        return False

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


# Global dictionary to track active flows
sessions = {}

def process_packet(packet, logs_col):
    if not packet.haslayer(IP):
        return

    now = datetime.now(timezone.utc)
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto_str = PROTO_MAP.get(packet[IP].proto, "other")
    
    # Identify ports
    sport = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
    dport = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)

    # 1. Create a unique key for the flow (Direction Neutral)
    # We use sorted IPs/Ports so (A->B) and (B->A) hit the same session
    flow_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))

    # 2. Initialize new session
    if flow_key not in sessions:
        sessions[flow_key] = {
            "hostname": AGENT_HOSTNAME,
            "start_time": now,
            "last_packet_time": now,
            "src_ip": src_ip, "dst_ip": dst_ip, # The first packet defines the 'Source'
            "src_port": sport, "dst_port": dport,
            "proto": proto_str,
            "sbytes": 0, "dbytes": 0,
            "spkts": 0, "dpkts": 0,
            "sttl": packet[IP].ttl, "dttl": 0,
            "stcpb": packet[TCP].seq if packet.haslayer(TCP) else 0, "dtcpb": 0,
            "syn_time": now if (packet.haslayer(TCP) and 'S' in packet[TCP].flags) else None,
            "synack_time": None,
            "ackdat": 0, "synack": 0,
            "state": "REQ"
        }

    session = sessions[flow_key]
    
    # 3. Determine direction (Is this packet from the Source or the Destination?)
    is_source = (src_ip == session["src_ip"] and sport == session["src_port"])
    
    # 4. Update metrics (Aggregation)
    pkt_len = len(packet)
    if is_source:
        session["sbytes"] += pkt_len
        session["spkts"] += 1
        session["last_packet_time"] = now
    else:
        session["dbytes"] += pkt_len
        session["dpkts"] += 1
        if session["dttl"] == 0: session["dttl"] = packet[IP].ttl
        if session["dtcpb"] == 0 and packet.haslayer(TCP): session["dtcpb"] = packet[TCP].seq

    # 5. Handle TCP Handshake Timing (matching synack/ackdat)
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        # If SYN-ACK from destination
        if not is_source and 'S' in flags and 'A' in flags:
            if session["syn_time"]:
                session["synack"] = (now - session["syn_time"]).total_seconds()
                session["synack_time"] = now
            session["state"] = "CON"
        # If ACK from source completing handshake
        elif is_source and 'A' in flags and session["synack_time"]:
            session["ackdat"] = (now - session["synack_time"]).total_seconds()
            session["synack_time"] = None # Reset so we don't recalculate

    # 6. Check for Termination (FIN / RST)
    should_ship = False
    if packet.haslayer(TCP):
        if 'F' in flags or 'R' in flags:
            session["state"] = "FIN" if 'F' in flags else "RST"
            should_ship = True
    elif proto_str == "udp":
        # For UDP, since there is no 'FIN', we usually ship after X packets 
        # or a timeout. For now, let's ship after 2 packets (Req/Res) to see data.
        if session["dpkts"] >= 1:
            should_ship = True

    # 7. Ship to MongoDB and Clear Session
    if should_ship:
        duration = (now - session["start_time"]).total_seconds()
        
        # Calculate final log matching UNSW-NB15 structure
        final_log = {
            "hostname": session["hostname"],
            "timestamp": now,
            "src_ip": session["src_ip"], "dst_ip": session["dst_ip"],
            "src_port": session["src_port"], "dst_port": session["dst_port"],
            "proto": session["proto"],
            "state": session["state"],
            "dur": duration,
            "sbytes": session["sbytes"], "dbytes": session["dbytes"],
            "sttl": session["sttl"], "dttl": session["dttl"],
            "stcpb": session["stcpb"], "dtcpb": session["dtcpb"],
            "synack": session["synack"], "ackdat": session["ackdat"],
            "processed": False
        }
        
        # Filter DB noise
        if final_log["dst_port"] not in [27017, 8000]:
            try:
                logs_col.insert_one(final_log)
            except Exception: pass
        
        del sessions[flow_key]


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
                        {"$set": {
                            "hostname": AGENT_HOSTNAME, # Track which host owns this baseline
                            "hash": file_hash, 
                            "last_check": time.time()
                        }},
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
                        # --- ADDED HOSTNAME HERE ---
                        alert = {
                            "hostname": AGENT_HOSTNAME, 
                            "type": "FIM_NEW_FILE", 
                            "file": full_path, 
                            "severity": "medium"
                        }
                        send_fim_alert(alert)
                        alerts_col.insert_one({**alert, "time": time.ctime(), "hash": current_hash})
                        baseline[full_path] = current_hash
                        hashes_col.update_one({"filepath": full_path}, {"$set": {"hash": current_hash}}, upsert=True)

                    elif current_hash != baseline[full_path]:
                        # --- ADDED HOSTNAME HERE ---
                        alert = {
                            "hostname": AGENT_HOSTNAME, 
                            "type": "FIM_MODIFICATION", 
                            "file": full_path, 
                            "severity": "high"
                        }
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
                    # --- ADDED HOSTNAME HERE ---
                    alert = {
                        "hostname": AGENT_HOSTNAME, 
                        "type": "FIM_DELETION", 
                        "file": path, 
                        "severity": "critical"
                    }
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
    LOG_FILE = "/var/log/nginx/access.log"
    
    if not os.path.exists(LOG_FILE):
        print(f"[!] Log Shipper: {LOG_FILE} not found. Monitoring active for Network and FIM only.")
        return # Thread finishes cleanly

    db = client.siem_db
    logs_col = db.raw_logs
    print(f"[*] Log Shipper active. Tailing {LOG_FILE}...")
    
    proc = subprocess.Popen(
        ['tail', '-F', LOG_FILE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    while True:
        line = proc.stdout.readline()
        if line:
            clean_line = line.strip()
            log_entry = {
                "hostname": AGENT_HOSTNAME, # Use the hostname here too!
                "source": "nginx-access-logs",
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
    global AGENT_HOSTNAME

    # --- STEP 1: GET THE HOSTNAME ---
    if len(sys.argv) > 1:
        AGENT_HOSTNAME = sys.argv[1]
    else:
        try:
            AGENT_HOSTNAME = input("Enter The AGENT_HOSTNAME: ").strip()
        except EOFError:
            AGENT_HOSTNAME = os.uname()[1]
            
        if not AGENT_HOSTNAME:
            AGENT_HOSTNAME = os.uname()[1]

    # --- STEP 2: HANDLE PERMISSIONS & ELEVATION ---
    if not check_permissions():
        if os.geteuid() != 0:
            print(f"[*] SIEM Agent [{AGENT_HOSTNAME}] requires elevation.")
            try:
                user = getpass.getuser()
                pwd = getpass.getpass(prompt=f"[?] Enter sudo password for {user}: ")
                cmd = ["sudo", "-S", "python3", sys.argv[0], AGENT_HOSTNAME]
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
                proc.communicate(input=pwd + "\n")
                sys.exit(proc.returncode)
            except Exception as e:
                print(f"[!] Elevation failed: {e}")
                sys.exit(1)
        else:
            print("[!] Fatal: Even as root, packet capture is unavailable.")
            sys.exit(1)

    # --- STEP 3: MONGODB CONNECTION ---
    client = None
    while True:
        try:
            print(f"[*] Connecting to SIEM MongoDB at {SIEM_DB_URL}...")
            client = MongoClient(SIEM_DB_URL, serverSelectionTimeoutMS=2000)
            client.admin.command('ping')
            print("[+] Successfully connected!")
            break
        except Exception as e:
            print(f"[!] Connection failed: {e}. Retrying in 5s...")
            time.sleep(5)

    # --- STEP 4: DAEMONIZE FIRST (FOR WEBSITE) ---
    # We fork BEFORE starting threads to avoid the DeprecationWarning/Deadlock

    if os.path.exists("/usr/sbin/nginx"):
        pid = os.fork()
        if pid > 0:
            os._exit(0) # Parent dies, letting Nginx start
            
        # Child continues here...
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')

    # --- STEP 5: START THREADS (ONLY ONCE) ---
    # This runs in the Child (Website) OR the Main Process (Machine)
    threading.Thread(target=run_fim_monitor, args=(client,), daemon=True).start()
    threading.Thread(target=start_network_sniffer, args=(client,), daemon=True).start()
    threading.Thread(target=start_log_shipper, args=(client,), daemon=True).start()

    # If we are NOT in the background (Machine mode), stay in foreground
    if not os.path.exists("/usr/sbin/nginx"):
        print(f"[!] SIEM Agent [{AGENT_HOSTNAME}] is fully operational.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Shutting down...")
    else:
        # In Website mode, the daemon just sleeps to keep threads alive
        while True:
            time.sleep(60)

if __name__ == "__main__":
    main()


