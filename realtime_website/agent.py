import time
import subprocess
from pymongo import MongoClient
import sys
import hashlib
import requests
from collections import defaultdict
import os
import threading
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime, timezone
import statistics
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
BACKEND_URL = ""


# ─────────────────────────────────────────────────────────────────────────────
# NEW FEATURE: Per-IP tracking windows (for connections_per_ip_window,
#              unique_ports_per_ip, failed_connection_ratio)
# ─────────────────────────────────────────────────────────────────────────────
IP_WINDOW_SECONDS = 60          # sliding window width (seconds)
ip_conn_times = defaultdict(list)   # src_ip -> [timestamps of connections]
ip_ports_seen = defaultdict(set)    # src_ip -> {dst_ports contacted}
ip_failed_counts = defaultdict(int)    # src_ip -> count of failed (INT/RST) flows
ip_total_counts = defaultdict(int)    # src_ip -> total flows initiated
ip_lock = threading.Lock()    # thread-safety for the dicts above


def _prune_window(src_ip, now_ts):
    """Remove connection timestamps outside the sliding window for src_ip."""
    cutoff = now_ts - IP_WINDOW_SECONDS
    ip_conn_times[src_ip] = [t for t in ip_conn_times[src_ip] if t >= cutoff]



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
        if not os.path.isfile(filepath):
            return None
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None


def creating_hostname_collection(hostname, client):
    db = client.siem_db
    agents_col = db.agents

    host_data = {
        "hostname": hostname,
        "first_seen": datetime.now(timezone.utc),
        "last_active": datetime.now(timezone.utc),
        "status": "online"
    }

    try:
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
    proto_num = packet[IP].proto
    proto_str = PROTO_MAP.get(proto_num, "other")

    sport = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
    dport = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)

    flow_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))

    if flow_key not in sessions:
        sessions[flow_key] = {
            "hostname": AGENT_HOSTNAME,
            "start_time": now,
            "last_packet_time": now,
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": sport, "dst_port": dport,
            "proto": proto_str,
            "sbytes": 0, "dbytes": 0,
            "spkts": 0, "dpkts": 0,
            "sttl": packet[IP].ttl, "dttl": 0,
            "stcpb": packet[TCP].seq if packet.haslayer(TCP) else 0, "dtcpb": 0,
            "syn_time": now if (packet.haslayer(TCP) and 'S' in packet[TCP].flags) else None,
            "synack_time": None,
            "synack": 0, "ackdat": 0,
            "state": "REQ",
            "timestamps": [now.timestamp()],
            "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0,
            "ports_seen": {dport}
        }

        with ip_lock:
            ip_conn_times[src_ip].append(now.timestamp())
            ip_ports_seen[src_ip].add(dport)
            ip_total_counts[src_ip] += 1

    session = sessions[flow_key]
    is_source = (src_ip == session["src_ip"] and sport == session["src_port"])
    pkt_len = len(packet)

    session["timestamps"].append(now.timestamp())
    session["last_packet_time"] = now
    session["ports_seen"].add(dport)

    if is_source:
        session["sbytes"] += pkt_len
        session["spkts"] += 1
    else:
        session["dbytes"] += pkt_len
        session["dpkts"] += 1
        if session["dttl"] == 0:
            session["dttl"] = packet[IP].ttl
        if session["dtcpb"] == 0 and packet.haslayer(TCP):
            session["dtcpb"] = packet[TCP].seq

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if 'S' in flags:
            session["syn_count"] += 1
        if 'A' in flags:
            session["ack_count"] += 1
        if 'F' in flags:
            session["fin_count"] += 1
        if 'R' in flags:
            session["rst_count"] += 1

        if not is_source and 'S' in flags and 'A' in flags:
            if session["syn_time"]:
                session["synack"] = (now - session["syn_time"]).total_seconds()
                session["synack_time"] = now
            session["state"] = "CON"
        elif is_source and 'A' in flags and session["synack_time"]:
            session["ackdat"] = (now - session["synack_time"]).total_seconds()
            session["synack_time"] = None

    duration = (now - session["start_time"]).total_seconds()
    should_ship = False

    if packet.haslayer(TCP) and ('F' in packet[TCP].flags or 'R' in packet[TCP].flags):
        session["state"] = "FIN" if 'F' in packet[TCP].flags else "RST"
        should_ship = True
    elif duration >= 10:
        should_ship = True
    elif (session["spkts"] + session["dpkts"]) > 50:
        should_ship = True

    if should_ship:
        if session["syn_count"] == 0 and (session["spkts"] > 0 and session["dpkts"] > 0):
            session["state"] = "CON"
        elif session["syn_count"] > 0 and session["dpkts"] == 0:
            session["state"] = "INT"

        if session["state"] in ("INT", "RST"):
            with ip_lock:
                ip_failed_counts[session["src_ip"]] += 1

        iat_list = [t2 - t1 for t1, t2 in zip(session["timestamps"], session["timestamps"][1:])]
        mean_iat = statistics.mean(iat_list) if iat_list else 0
        std_iat = statistics.stdev(iat_list) if len(iat_list) > 1 else 0

        total_pkts = session["spkts"] + session["dpkts"]
        total_bytes = session["sbytes"] + session["dbytes"]

        service = "-"
        if session["dst_port"] in SERVICE_MAP:
            service = SERVICE_MAP.get(session["dst_port"], "-")
        elif session["src_port"] in SERVICE_MAP:
            service = SERVICE_MAP.get(session["src_port"], "-")

        flow_bytes = total_bytes
        bytes_per_pkt = (total_bytes / total_pkts) if total_pkts > 0 else 0
        syn_ratio = (session["syn_count"] / total_pkts) if total_pkts > 0 else 0
        ack_ratio = (session["ack_count"] / total_pkts) if total_pkts > 0 else 0
        rst_ratio = (session["rst_count"] / total_pkts) if total_pkts > 0 else 0
        iat_ratio = (std_iat / mean_iat) if mean_iat > 0 else 0

        flow_src_ip = session["src_ip"]
        now_ts = now.timestamp()
        with ip_lock:
            _prune_window(flow_src_ip, now_ts)
            unique_ports_per_ip = len(ip_ports_seen[flow_src_ip])
            connections_per_ip_window = len(ip_conn_times[flow_src_ip])
            total_for_ip = ip_total_counts[flow_src_ip]
            failed_for_ip = ip_failed_counts[flow_src_ip]
            failed_connection_ratio = (failed_for_ip / total_for_ip) if total_for_ip > 0 else 0

        # Ensure duration is at least 0.001 to prevent zero-rate issues
        eff_dur = duration if duration > 0.001 else 0.001

        # VETERAN FIX: Port scans are fast (low duration) but high impact
        # We mark it significant if it's very fast OR has many packets
        is_significant = True
        if total_pkts < 3 and duration > 5:
            is_significant = False

        final_log = {
            "hostname": session["hostname"],
            "timestamp": now.isoformat(),
            "src_ip": session["src_ip"], "dst_ip": session["dst_ip"],
            "src_port": session["src_port"], "dst_port": session["dst_port"],
            "proto": session["proto"],
            "state": session["state"],
            "service": service,
            "dur": duration,
            "spkts": session["spkts"], "dpkts": session["dpkts"],
            "sbytes": session["sbytes"], "dbytes": session["dbytes"],
            "sttl": session["sttl"], "dttl": session["dttl"],
            "synack": session["synack"], "ackdat": session["ackdat"],
            "stcpb": session["stcpb"], "dtcpb": session["dtcpb"],
            "rate": (total_bytes / eff_dur),
            "pkt_rate": (total_pkts / eff_dur),
            "byte_rate": (total_bytes / eff_dur),
            "is_significant": is_significant,
            "flow_ratio": session["spkts"] / (session["dpkts"] + 1),
            "syn_count": session["syn_count"],
            "ack_count": session["ack_count"],
            "fin_count": session["fin_count"],
            "rst_count": session["rst_count"],
            "mean_iat": mean_iat,
            "std_iat": std_iat,
            "flow_packets": total_pkts,
            "port_count": len(session["ports_seen"]),
            "flow_bytes": flow_bytes,
            "bytes_per_pkt": bytes_per_pkt,
            "syn_ratio": syn_ratio,
            "ack_ratio": ack_ratio,
            "rst_ratio": rst_ratio,
            "iat_ratio": iat_ratio,
            "unique_ports_per_ip": unique_ports_per_ip,
            "connections_per_ip_window": connections_per_ip_window,
            "failed_connection_ratio": failed_connection_ratio,
            "processed": False
        }

        if final_log["dst_port"] not in [27018, 8000] and final_log["src_port"] not in [27018, 8000]:
            try:
                requests.post(NETWORK_BACKEND_URL, json=final_log, timeout=10)
            except Exception as e:
                print(f"[!] Shipping failed: {e}")

        del sessions[flow_key]


def start_network_sniffer(client):
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
                            "hostname": AGENT_HOSTNAME,
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
                    if not current_hash:
                        continue

                    if full_path not in baseline:
                        alert = {
                            "hostname": AGENT_HOSTNAME,
                            "type": "FIM_NEW_FILE",
                            "file": full_path,
                            "severity": "medium"
                        }
                        send_fim_alert(alert)
                        baseline[full_path] = current_hash
                        hashes_col.update_one({"filepath": full_path}, {"$set": {"hash": current_hash}}, upsert=True)

                    elif current_hash != baseline[full_path]:
                        alert = {
                            "hostname": AGENT_HOSTNAME,
                            "type": "FIM_MODIFICATION",
                            "file": full_path,
                            "severity": "high"
                        }
                        send_fim_alert(alert)
                        baseline[full_path] = current_hash
                        hashes_col.update_one({"filepath": full_path}, {"$set": {"hash": current_hash}})

        baseline_paths = list(baseline.keys())
        for path in baseline_paths:
            if path not in files_found_on_disk:
                if any(path.startswith(watched) for watched in watch_list):
                    alert = {
                        "hostname": AGENT_HOSTNAME,
                        "type": "FIM_DELETION",
                        "file": path,
                        "severity": "critical"
                    }
                    print(f"[!!] DELETION DETECTED: {path}")
                    send_fim_alert(alert)
                    del baseline[path]
                    hashes_col.delete_one({"filepath": path})


def send_fim_alert(data):
    try:
        requests.post(BACKEND_URL, json=data, timeout=15)
    except Exception as e:
        print(f"[!] Failed to ship alert: {e}")



def main():
    global AGENT_HOSTNAME, SIEM_DB_URL, NETWORK_BACKEND_URL, CONFIG_URL, BACKEND_URL

    parser = argparse.ArgumentParser(
        description="This is agent.py for windows"
    )
    parser.add_argument("--siem_db_url", type=str, default="mongodb://172.17.0.1:27018/", help="used to provide the siem database url")
    parser.add_argument("--network_backend_url", type=str, default="http://172.17.0.1:8000/api/logs", help="used to provide the network alert to backend")
    parser.add_argument("--config_url", type=str, default="http://172.17.0.1:8000/api/config", help="used to provide the config url")
    parser.add_argument("--backend_url", type=str, default="http://172.17.0.1:8000/api/alerts", help="used to provide backend url")
    parser.add_argument("--agent_hostname", type=str, default="no_nameHostname", help="used to provide agent hostname")

    arguments = parser.parse_args()
    SIEM_DB_URL = arguments.siem_db_url
    NETWORK_BACKEND_URL = arguments.network_backend_url
    CONFIG_URL = arguments.config_url
    BACKEND_URL = arguments.backend_url
    AGENT_HOSTNAME = arguments.agent_hostname

    if not check_permissions():
        if os.geteuid() != 0:
            print(f"[*] SIEM Agent [{AGENT_HOSTNAME}] requires elevation.")
            try:
                user = getpass.getuser()
                pwd = getpass.getpass(prompt=f"[?] Enter sudo password for {user}: ")
                cmd = ["sudo", "-S", "python3", sys.argv[0], AGENT_HOSTNAME]
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
                proc.communicate(input=pwd + " ")
                sys.exit(proc.returncode)
            except Exception as e:
                print(f"[!] Elevation failed: {e}")
                sys.exit(1)
        else:
            print("[!] Fatal: Even as root, packet capture is unavailable.")
            sys.exit(1)

    if os.path.exists("/usr/sbin/nginx"):
        print("[*] Launching Nginx and backgrounding SIEM Agent...")
        pid = os.fork()
        if pid > 0:
            return

        sys.stdout = open('/var/log/siem_agent.log', 'a', buffering=1)
        sys.stderr = open('/var/log/siem_agent.err', 'a', buffering=1)

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

    creating_hostname_collection(AGENT_HOSTNAME, client)

    security_modules = [
        (run_fim_monitor, "FIM Integrity Watcher"),
        (start_network_sniffer, "Flow Aggregator (Network)"),
    ]

    for target_func, name in security_modules:
        thread = threading.Thread(target=target_func, args=(client,), daemon=True)
        thread.start()
        print(f"[+] Started {name} thread.")

    if not os.path.exists("/usr/sbin/nginx"):
        print(f"--- SIEM Agent [{AGENT_HOSTNAME}] is fully operational ---")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Shutdown signal received. Closing Agent...")
        client.close()
        sys.exit(0)


if __name__ == "__main__":
    main()
