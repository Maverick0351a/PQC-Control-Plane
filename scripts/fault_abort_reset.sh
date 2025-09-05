#!/usr/bin/env bash
set -euo pipefail

echo "[fault_abort_reset] Removing TCP abort rule(s) for port 8443 in nginx container"
docker compose exec --user root nginx sh -lc '
  apk add --no-cache iptables >/dev/null 2>&1 || true;
  # Attempt to delete matching rules until none remain
  while iptables -C INPUT -p tcp --dport 8443 -m statistic --mode random --probability 0.3 -j REJECT --reject-with tcp-reset 2>/dev/null; do
    iptables -D INPUT -p tcp --dport 8443 -m statistic --mode random --probability 0.3 -j REJECT --reject-with tcp-reset || break;
  done;
  echo " - remaining INPUT rules for 8443:";
  iptables -S INPUT | grep -- '--dport 8443' || echo "   (none)";
'
echo "[fault_abort_reset] Done"
