#!/usr/bin/env bash
set -euo pipefail

echo "[netem_reset] Removing network impairment from nginx container; restoring defaults (mtu=1500)"
docker compose exec --user root nginx sh -lc '
  tc qdisc del dev eth0 root 2>/dev/null || true;
  ip link set dev eth0 mtu 1500 || true;
  echo " - qdisc cleared and MTU reset";
  tc qdisc show dev eth0;
'
echo "[netem_reset] Done"
