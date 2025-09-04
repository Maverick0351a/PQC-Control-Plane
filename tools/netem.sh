#!/usr/bin/env bash
set -euo pipefail

IFACE=${1:-veth-client}
MTU=${2:-1300}
LOSS=${3:-0.1}

echo "[*] Setting MTU on $IFACE to $MTU"
sudo ip link set dev "$IFACE" mtu "$MTU"

echo "[*] Applying netem loss $LOSS% on $IFACE"
sudo tc qdisc add dev "$IFACE" root netem loss "$LOSS"% || sudo tc qdisc change dev "$IFACE" root netem loss "$LOSS"%

echo "[*] Done."
