#!/usr/bin/env bash
set -euo pipefail

echo "[fault_abort] Injecting random TCP abort (RST) rule on port 8443 (probability=30%) in nginx container"
docker compose exec --user root nginx sh -lc '
  apk add --no-cache iptables >/dev/null 2>&1 || true;
  echo " - ensuring iptables present";
  iptables -I INPUT -p tcp --dport 8443 -m statistic --mode random --probability 0.3 -j REJECT --reject-with tcp-reset || true;
  echo " - rule inserted";
  iptables -S INPUT | grep -- '--dport 8443' || echo " - warning: rule not found in listing";
'
echo "[fault_abort] Done"
