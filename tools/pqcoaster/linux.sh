#!/usr/bin/env bash
# PQCoaster Linux: MSS clamp + allow ICMP PTB + enable PLPMTUD.
# Idempotent: safe to run multiple times.
set -euo pipefail

MSS=${PQCOASTER_MSS:-1200}

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables not found; require NET_ADMIN capabilities" >&2
  exit 1
fi

# Remove existing identical rule (avoid duplicates)
iptables -t mangle -S | grep -F "--set-mss ${MSS}" >/dev/null 2>&1 || \
  sudo iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${MSS}

# Allow fragmentation-needed (ICMP PTB, IPv4 type 3 code 4)
iptables -S | grep -i "fragmentation-needed" >/dev/null 2>&1 || \
  sudo iptables -A INPUT -p icmp --icmp-type fragmentation-needed -j ACCEPT

# Allow IPv6 Packet Too Big (type 2)
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -S | grep -i "type 2" >/dev/null 2>&1 || \
    sudo ip6tables -A INPUT -p icmpv6 --icmpv6-type 2 -j ACCEPT
fi

# Enable PLPMTUD probing (mode 1 = weak, 2 = strong)
sudo sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null

echo "[pqcoaster] Applied MSS clamp=${MSS}, enabled ICMP PTB + PLPMTUD"
