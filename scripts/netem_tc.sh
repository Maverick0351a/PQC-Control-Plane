#!/usr/bin/env bash
set -euo pipefail

echo "[netem_tc] Applying network impairment to nginx container (loss=1% delay=50ms±10ms mtu=1300)"
docker compose exec --user root nginx sh -lc '
  apk add --no-cache iproute2 >/dev/null 2>&1 || true;
  echo " - installing iproute2 (if needed)";
  tc qdisc replace dev eth0 root netem loss 1% delay 50ms 10ms distribution normal;
  echo " - applied tc netem qdisc";
  ip link set dev eth0 mtu 1300;
  echo " - set MTU 1300";
  tc qdisc show dev eth0;
'
echo "[netem_tc] Done"
