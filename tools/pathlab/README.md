PathLab (Dev/Test Impairment Proxy)
===================================

Lightweight placeholder for TLS / path impairment scenarios used in CI:

Scenarios (planned):
- ABORT_AFTER_CH: close TCP connection right after ClientHello bytes received.
- MTU1300_BLACKHOLE: Drop outbound packets >1300 bytes to simulate PMTUD blackhole.

Current state: placeholder documentation. Implementation will ship as a container image (ghcr.io/yourorg/pathlab:latest) invoked via docker-compose profile `dev`.

Usage (future):
```
pathlab --listen :4040 --upstream nginx:443 --scenario ABORT_AFTER_CH
```
