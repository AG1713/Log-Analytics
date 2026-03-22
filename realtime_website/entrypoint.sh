#!/bin/bash

echo "[*] Starting Security Services (SSH & FTP)..."
service ssh start
service vsftpd start

echo "[*] Starting SIEM Log Agent..."
# Start the agent in the background
python3 -u /usr/local/bin/agent.py &

echo "[*] Launching Nginx Web Server..."
# Start Nginx in the foreground so the container stays alive
exec nginx -g "daemon off;"
