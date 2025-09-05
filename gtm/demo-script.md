# 5‑Minute Live Demo Script

Goal: Show closed‑loop assurance: Policy → Enforcement → Proof (with breaker + PQC option).

## 0. Prep
```powershell
docker compose up -d --build redis app envoy prometheus grafana
# (Optional faults) docker compose -f docker-compose.yml -f sandbox/toxiproxy/docker-compose.override.yml up -d
```

## 1. Handshake Challenge & Signed Request
```powershell
curl.exe -k -I https://localhost:8443/protected | findstr /R "401 PCH-Challenge"
python .\tools\pch_client_demo.py --url https://localhost:8443/protected --binding tls-exporter --insecure
```
Show receipt tail (JSONL) or `/metrics` counters increment.

## 2. PQC / Hybrid (if available)
```powershell
python .\tools\pch_client_demo.py --url https://localhost:8443/protected --binding tls-exporter --alg ml-dsa-65 --insecure
python .\tools\pch_client_demo.py --url https://localhost:8443/protected --binding tls-exporter --alg ecdsa-p256+ml-dsa-65 --insecure
```
Point out `alg` field in receipt.

## 3. Breaker Under Stress (Latency Injection)
```powershell
# (If toxiproxy) scripts\faults\run_faults.ps1 -Iterations 60
```
Open Grafana (panel: Breaker State, EWMA error, Rho). Narrate Closed→Open→HalfOpen→Closed.

## 4. Relax Header Budget (Optional)
Use demo client with large evidence flag (if implemented) to trigger 431/428 and retry.

## 5. Compliance Pack & Verification
```powershell
$date = (Get-Date).ToString('yyyy-MM-dd')
curl.exe -X POST http://localhost:8080/compliance/pack -H "Content-Type: application/json" -d '{"date":"'+$date+'"}' -o pack.zip
# unzip pack.zip then show sth.json & receipts.jsonl
```
Explain Merkle root & STH chain hash.

## 6. Policy Safety (Rego)
Open `policy/shield.rego`. Temporarily raise availability floor, re-run a request with simulated high 5xx (describe) → fallback action in receipt controller section.

## 7. Close
Summarize: Proof delivered (receipts + STH) < 5 min; breaker stability; PQC future‑proofing.
