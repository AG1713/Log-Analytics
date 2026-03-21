import time
import subprocess
from pymongo import MongoClient
import sys
import hashlib
import requests
import os
import threading

# --- CONFIGURATION ---
SIEM_DB_URL = "mongodb://172.17.0.1:27017/"
# These are used only if the Backend API is unreachable
DEFAULT_PATHS = ["/etc/nginx", "/var/www/html", "/root", "/var/log/nginx"] 
CHECK_INTERVAL = 2 
BACKEND_URL = "http://172.17.0.1:8000/api/alerts"
CONFIG_URL = "http://172.17.0.1:8000/api/config" # The new endpoint we added to main.py

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

    # Start FIM in the background thread
    fim_thread = threading.Thread(target=run_fim_monitor, args=(client,), daemon=True)
    fim_thread.start()

    # Start Log Shipper in the main thread
    try:
        start_log_shipper(client)
    except KeyboardInterrupt:
        print("\n[!] Agent shutting down...")

if __name__ == "__main__":
    main()
