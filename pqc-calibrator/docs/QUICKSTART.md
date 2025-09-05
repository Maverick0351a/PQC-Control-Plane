# QUICKSTART — PQC Calibrator VM (MVP)

1) Build (optional) VM image with Packer
- See `packer/ubuntu-22.pkr.hcl` and `scripts/*.sh` for provisioning steps.

2) Run the calibrator stack
- cd `pqc-calibrator/compose`
- docker compose up -d --build
- Services:
  - PathLab admin: http://localhost:15001
  - PQC Go Server (HTTP MVP): http://localhost:8443/hello
  - Prometheus: http://localhost:9090
  - Grafana: http://localhost:3000

3) Try the client
- docker compose run --rm pqc-go-client

Notes
- TLS_GROUPS is surfaced by server but not enforced (MVP). Swap to a TLS stack with PQC ciphers/groups later.
- pqcoaster is a placeholder container (needs host networking + privileged for tc/iptables).
