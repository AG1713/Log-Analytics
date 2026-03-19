#!/bin/bash

# 1. Start the Python Log Agent in the BACKGROUND
# The '&' is crucial here so the script continues to the next line
python3 -u /usr/local/bin/agent.py &

# 2. Start Nginx in the FOREGROUND
nginx -g "daemon off;"
