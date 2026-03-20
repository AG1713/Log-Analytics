import time
import subprocess
from pymongo import MongoClient
import sys
import hashlib
import requests
import os
import threading

# Using the 172.19.0.1 Gateway for your Parrot OS Docker Bridge
SIEM_DB_URL = "mongodb://172.17.0.1:27017/"
WATCH_PATHS = ["/etc/nginx", "/var/www/html", "/root"] # Change these according to User
CHECK_INTERVAL = 60  # seconds
BACKEND_URL = "http://backend:8000/api/alerts" # Your FastAPI endpoint

def calculate_sha256(filepath):
    """Generates a SHA256 hash for a specific file."""
    sha256_hash = hashlib.sha256()
    try:
        if not os.path.isfile(filepath): return None
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError):
        print("Permission Not Present")
        return None

def run_fim_monitor(client):
    """
    Background thread logic for monitoring file integrity.
    Detects New, Modified, and DELETED files.
    """
    # --- STEP 1: Setup FIM Collections ---
    fim_db = client.fim_integrity
    hashes_col = fim_db.file_baselines
    alerts_col = fim_db.fim_alerts

    # --- STEP 2: Establish Initial Baseline ---
    print("[*] FIM: Establishing Initial Baseline...")
    baseline = {}
    for path in WATCH_PATHS:
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file) # example: root:/etc/nginx file:access
                file_hash = calculate_sha256(full_path)
                if file_hash:
                    baseline[full_path] = file_hash # Captures the initial baseline, i.e a reference for checking the next file hashes
                    hashes_col.update_one( # Updated the hashes column
                        {"filepath": full_path},
                        {"$set": {"hash": file_hash, "last_check": time.time()}},
                        upsert=True
                    )
    print("[+] FIM: Baseline synced. Monitoring active.")

    # --- STEP 3: Continuous Integrity Loop ---
    while True:
        time.sleep(CHECK_INTERVAL)
        
        # Track which files we find during THIS scan to detect deletions later
        files_found_on_disk = set()

        for path in WATCH_PATHS:
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    files_found_on_disk.add(full_path) # Mark file as present, i.e the file is present in the path as expected
                    
                    current_hash = calculate_sha256(full_path)
                    if not current_hash: continue

                    # --- DETECT NEW FILES ---
                    if full_path not in baseline: # initially the file was not present in the directory/folder, but it is present now
                        alert = {"type": "FIM_NEW_FILE", "file": full_path, "severity": "medium"}
                        send_fim_alert(alert)
                        alerts_col.insert_one({**alert, "time": time.ctime(), "hash": current_hash}) # add to the alert's column
                        baseline[full_path] = current_hash
                        hashes_col.insert_one({"filepath": full_path, "hash": current_hash})

                    # --- DETECT MODIFICATIONS ---
                    elif current_hash != baseline[full_path]: # if the files in baseline files is not present, i.e it is modified 
                        alert = {"type": "FIM_MODIFICATION", "file": full_path, "severity": "high"}
                        send_fim_alert(alert)
                        alerts_col.insert_one({
                            **alert, "time": time.ctime(), 
                            "old_hash": baseline[full_path], "new_hash": current_hash
                        })
                        baseline[full_path] = current_hash
                        hashes_col.update_one({"filepath": full_path}, {"$set": {"hash": current_hash}})

        # --- STEP 4: DETECT DELETIONS ---
        # We compare our Baseline keys against the files we actually found on disk
        baseline_paths = list(baseline.keys())
        for path in baseline_paths:
            if path not in files_found_on_disk:
                # The file was in our baseline but is now GONE from the disk
                alert = {"type": "FIM_DELETION", "file": path, "severity": "critical"}
                
                print(f"[!!] DELETION DETECTED: {path}")
                send_fim_alert(alert)
                
                # Log the deletion alert to MongoDB
                alerts_col.insert_one({**alert, "time": time.ctime()})
                
                # Remove from baseline and MongoDB so we don't keep alerting
                del baseline[path]
                hashes_col.delete_one({"filepath": path})

def send_fim_alert(data):
    """Sends integrity alerts to the FastAPI backend."""
    try:
        requests.post(BACKEND_URL, json=data, timeout=5)
        print(f"[!] FIM Alert Sent: {data['file']}")
    except Exception as e:
        print(f"[!] Failed to send FIM alert: {e}")

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
