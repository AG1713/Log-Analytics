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
import argparse


# --- CONFIGURATION ---
DEFAULT_PATHS = ["/etc/nginx", "/var/www/html"] 
CHECK_INTERVAL = 10 
SERVICE_MAP = {80: "http", 443: "http", 53: "dns", 21: "ftp", 22: "ssh"}
PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}
AGENT_HOSTNAME = ""
SIEM_DB_URL = ""
NETWORK_BACKEND_URL = ""
CONFIG_URL = ""

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

def creating_hostname_collection(hostname, client):
    db = client.siem_db
    # We call the collection 'agents' or 'host_registry'
    agents_col = db.agents 
    
    # Metadata to store about the host
    host_data = {
        "hostname": hostname,
        "first_seen": datetime.now(timezone.utc),
        "last_active": datetime.now(timezone.utc),
        "status": "online"
    }

    try:
        # 'upsert=True' is the key here: 
        # It updates 'last_active' if host exists, 
        # or inserts the whole 'host_data' if it's new.
        agents_col.update_one(
            {"hostname": hostname},
            {"$set": {"last_active": datetime.now(timezone.utc)}, 
             "$setOnInsert": {"first_seen": datetime.now(timezone.utc)}},
            upsert=True
        )
        print(f"[+] Host [{hostname}] registered in siem_db.")
    except Exception as e:
        print(f"[!] Failed to register hostname: {e}")


# Global dictionary to track active flows
sessions = {}

def process_packet(packet):
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

    # 6. Check for Termination OR Timeout/Volume
    current_duration = (now - session["start_time"]).total_seconds()
    should_ship = False

    # Ship if: TCP closed, OR UDP has response, OR session is > 10 seconds, OR > 50 packets
    if packet.haslayer(TCP):
        flags = packet[TCP].flags # Moved inside the check
        if 'F' in flags or 'R' in flags:
            session["state"] = "FIN" if 'F' in flags else "RST"
            should_ship = True
        elif (session["spkts"] + session["dpkts"]) >= 1 and session["state"] == "REQ" and current_duration > 2:
            # This captures spoofed SYN floods faster for your SIEM
            session["state"] = "INT" # 'INT' for Interrupted/Incomplete
            should_ship = True
            
    elif proto_str == "udp":
        if session["dpkts"] >= 1 or current_duration > 5:
            should_ship = True

    elif current_duration > 10: 
        should_ship = True
        
    if (session["spkts"] + session["dpkts"]) > 50:
        should_ship = True
    # 7. Ship to MongoDB and Clear Session
    if should_ship:
        duration = (now - session["start_time"]).total_seconds()
        
        # Calculate final log matching UNSW-NB15 structure
        final_log = {
            "hostname": session["hostname"],
            "timestamp": now.isoformat(),
            "src_ip": session["src_ip"], "dst_ip": session["dst_ip"],
            "src_port": session["src_port"], "dst_port": session["dst_port"],
            "proto": session["proto"],
            "state": session["state"],
            "dur": duration,
            "sbytes": session["sbytes"], "dbytes": session["dbytes"],
            "spkts":session["spkts"], "dpkts":session["dpkts"],
            "sttl": session["sttl"], "dttl": session["dttl"],
            "stcpb": session["stcpb"], "dtcpb": session["dtcpb"],
            "synack": session["synack"], "ackdat": session["ackdat"],
            "processed": False
        }

        print(f"Shipping Flow: {src_ip} -> {dst_ip} ({session['state']})")
        
        # Filter DB noise
        temp=NETWORK_BACKEND_URL

        ip = temp.split("//")[1].split(":")[0]
        if final_log["dst_port"] not in [27018, 8000] and final_log["src_port"] not in [27018,8000]:
            try:
                print(f"[+] Attempting the ship logs to {NETWORK_BACKEND_URL}")
                response = requests.post(NETWORK_BACKEND_URL, json=final_log, timeout=15)
                print(f"[+] Server Response: {response.status_code}-{response.text}")
            except Exception as e:
                print(f"[!] Failed to ship log {e}")
        
        del sessions[flow_key]


def start_network_sniffer(client):
    #db = client.siem_db
    #logs_col = db.network_logs
    print("[*] Network Sniffer active. Capturing traffic...")
    sniff(prn=lambda pkt: process_packet(pkt), store=0)

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
    #alerts_col = fim_db.fim_alerts

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

    for doc in hashes_col.find({"hostname": AGENT_HOSTNAME}):
        baseline[doc["filepath"]] = doc["hash"]

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
                        #alerts_col.insert_one({**alert, "time": time.ctime(), "hash": current_hash})
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
                        #alerts_col.insert_one({
                            #**alert, "time": time.ctime(), 
                            #"old_hash": baseline[full_path], "new_hash": current_hash
                        #})
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
                    #alerts_col.insert_one({**alert, "time": time.ctime()})
                    del baseline[path]
                    hashes_col.delete_one({"filepath": path})

def send_fim_alert(data):
    try:
        requests.post(BACKEND_URL, json=data, timeout=15)
    except Exception as e:
        print(f"[!] Failed to ship alert: {e}")



def main():
    global AGENT_HOSTNAME, SIEM_DB_URL, NETWORK_BACKEND_URL, CONFIG_URL, BACKEND_URL

    parser =argparse.ArgumentParser(
            description = "This is agent.py for windows"
            )
    parser.add_argument("--siem_db_url",type=str, default="mongodb://172.17.0.1:27018/", help="used to provide the siem database url")
    parser.add_argument("--network_backend_url",type=str, default="http://172.17.0.1:8000/api/logs", help="used to provide the network alert to backend")
    parser.add_argument("--config_url",type=str, default="http://172.17.0.1:8000/api/config",help="used to provide the config url")
    parser.add_argument("--backend_url",type=str, default="http://172.17.0.1:8000/api/alerts",help="used to provide backend url")
    parser.add_argument("--agent_hostname",type=str, default="no_nameHostname", help="used to provide agent hostname")

    arguments=parser.parse_args()
    SIEM_DB_URL=arguments.siem_db_url
    NETWORK_BACKEND_URL=arguments.network_backend_url
    CONFIG_URL=arguments.config_url
    BACKEND_URL=arguments.backend_url
    AGENT_HOSTNAME=arguments.agent_hostname    


    # --- STEP 2: HANDLE PERMISSIONS & ELEVATION ---
    # Ensure we have the rights to sniff packets (requires root/cap_net_raw)
    if not check_permissions():
        if os.geteuid() != 0:
            print(f"[*] SIEM Agent [{AGENT_HOSTNAME}] requires elevation.")
            try:
                user = getpass.getuser()
                pwd = getpass.getpass(prompt=f"[?] Enter sudo password for {user}: ")
                # Re-run the script with sudo
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

    # --- STEP 5: DAEMONIZE FOR WEBSITE MODE ---
    # If Nginx is present, we fork to run the agent as a background daemon
    if os.path.exists("/usr/sbin/nginx"):
        print("[*] Launching Nginx and backgrounding SIEM Agent...")
        pid = os.fork()
        if pid > 0:
            # Parent process: Exits so the Docker entrypoint continues to Nginx
            return 
            
        # Child process: Continues as the background SIEM agent
        # Redirect standard IO to avoid cluttering the Nginx logs
        sys.stdout = open('/var/log/siem_agent.log', 'a',buffering=1)
        sys.stderr = open('/var/log/siem_agent.err', 'a', buffering=1)

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

    # --- STEP 4: REGISTER HOSTNAME ---
    # Do this before forking so the registry is updated immediately
    creating_hostname_collection(AGENT_HOSTNAME, client)


    # --- STEP 6: START MONITORING THREADS ---
    # We use a list to keep track of our security modules
    security_modules = [
        (run_fim_monitor, "FIM Integrity Watcher"),
        (start_network_sniffer, "Flow Aggregator (Network)"),
    ]

    for target_func, name in security_modules:
        thread = threading.Thread(target=target_func, args=(client,), daemon=True)
        thread.start()
        # Note: If backgrounded, these prints go to devnull
        print(f"[+] Started {name} thread.")

    # --- STEP 7: KEEP-ALIVE LOOP ---
    if not os.path.exists("/usr/sbin/nginx"):
        print(f"--- SIEM Agent [{AGENT_HOSTNAME}] is fully operational ---")
    
    try:
        while True:
            # You could add a 'heartbeat' here to update 'last_active' in MongoDB
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal received. Closing Agent...")
        client.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
