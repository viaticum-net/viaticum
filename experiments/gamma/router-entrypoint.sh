#!/bin/sh
set -e

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# MASQUERADE both private networks to outer-facing interfaces.
# We masquerade any traffic leaving the private subnets towards the outer net.
iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.20.0/24 -j MASQUERADE

# Allow forwarding between all interfaces.
iptables -P FORWARD ACCEPT

echo "Router ready. Forwarding enabled, MASQUERADE active."

# Block mode: if DROP_UDP env var is set, block direct UDP between inner nets.
if [ "${DROP_UDP:-0}" = "1" ]; then
    iptables -A FORWARD -p udp -s 192.168.10.0/24 -d 192.168.20.0/24 -j DROP
    iptables -A FORWARD -p udp -s 192.168.20.0/24 -d 192.168.10.0/24 -j DROP
    echo "UDP DROP rules installed (relay-only mode)."
fi

sleep infinity
