#!/bin/bash

echo "[*] Starting Log Agent on User Machine..."

# Run in the foreground so it can take keyboard input
# 'exec' is better because it makes Python the main process (PID 1)
sudo -S python3 /usr/local/bin/agent.py
