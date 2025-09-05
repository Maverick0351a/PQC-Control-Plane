#!/usr/bin/env bash
set -euo pipefail

apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl git make jq

# Placeholder: install Go for CLI and service samples
if ! command -v go >/dev/null 2>&1; then
  GO_VER=1.22.5
  curl -fsSL https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
  echo 'export PATH=/usr/local/go/bin:$PATH' >/etc/profile.d/go.sh
fi

# Placeholder: NodeJS or other tools as needed
