#!/bin/bash
set -e

# Ensure iptables directory exists
mkdir -p /etc/iptables

# Load iptables rules if they exist
if [ -f /etc/iptables/rules.v4 ]; then
    echo "Loading iptables rules..."
    iptables-restore < /etc/iptables/rules.v4
fi

# Start the responder
python responder.py
