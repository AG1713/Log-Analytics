import time
import subprocess
from pymongo import MongoClient
import sys

# Using the 172.19.0.1 Gateway for your Parrot OS Docker Bridge
SIEM_DB_URL = "mongodb://172.19.0.1:27017/"

def start_agent():
    # --- STEP 1: Connect to SIEM ---
    client = None
    while True:
        try:
            print(f"[*] Attempting to connect to SIEM at {SIEM_DB_URL}...")
            client = MongoClient(SIEM_DB_URL, serverSelectionTimeoutMS=2000)
            # The 'ping' command verifies the server is actually there
            client.admin.command('ping')
            print("[+] Successfully connected to SIEM MongoDB!")
            break
        except Exception as e:
            print(f"[!] SIEM not reachable: {e}. Retrying in 5 seconds...")
            time.sleep(5)

    # --- STEP 2: Setup Database ---
    db = client.siem_db
    logs_col = db.raw_logs

    # --- STEP 3: Start Tailing Logs ---
    # -F is "Follow" which handles log rotations if Nginx restarts
    print("[*] SIEM Agent active. Monitoring Ecommerce traffic...")
    proc = subprocess.Popen(
        ['tail', '-F', '/var/log/nginx/access.log'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # --- STEP 4: Ship Logs to Mongo ---
    while True:
        line = proc.stdout.readline()
        if line:
            clean_line = line.strip()
            log_entry = {
                "source": "ecommerce-production-site",
                "timestamp": time.time(),
                "raw_message": clean_line,
                "processed": False  # Your ML backend will set this to True later
            }
            
            try:
                logs_col.insert_one(log_entry)
                print(f"[+] Shipped: {clean_line[:60]}...")
            except Exception as e:
                print(f"[!] Failed to ship log: {e}")
        else:
            # Short sleep to prevent 100% CPU usage when idle
            time.sleep(0.1)

if __name__ == "__main__":
    start_agent()
