#!/bin/bash

echo "[*] Starting Security Services (SSH & FTP)..."
service ssh start
service vsftpd start

echo "[*] Starting SIEM Log Agent..."
# 1. Run the agent in the FOREGROUND first so it can take input
# 2. We don't use & here because we need the keyboard connection
python3 -u /usr/local/bin/agent.py 

# NOTE: Your Python script uses sys.exit(proc.returncode) 
# which might stop the script here. 
# To keep the container alive, we use 'exec' for Nginx at the end.

echo "[*] Launching Nginx Web Server..."
exec nginx -g "daemon off;"
