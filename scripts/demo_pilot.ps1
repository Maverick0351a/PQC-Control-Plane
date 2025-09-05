param(
  [switch]$IncludeFaults,
  [string]$Alg = 'ed25519'
)
$ErrorActionPreference='Stop'
Write-Host "[+] Starting core stack" -ForegroundColor Cyan
docker compose up -d --build redis app envoy prometheus grafana | Out-Null
Start-Sleep -Seconds 5

Write-Host "[+] Challenge" -ForegroundColor Cyan
curl.exe -k -I https://localhost:8443/protected

Write-Host "[+] Signed request ($Alg)" -ForegroundColor Cyan
python .\tools\pch_client_demo.py --url https://localhost:8443/protected --binding tls-exporter --alg $Alg --insecure

Write-Host "[+] Metrics snapshot" -ForegroundColor Cyan
curl.exe http://localhost:8080/__metrics | powershell -Command "$input | Select-String 'breaker' -Context 0,5"

if($IncludeFaults){
  Write-Host "[+] Launching fault harness (latency/bandwidth)" -ForegroundColor Yellow
  docker compose -f docker-compose.yml -f sandbox/toxiproxy/docker-compose.override.yml up -d toxiproxy | Out-Null
  Start-Sleep -Seconds 3
  scripts\faults\run_faults.ps1 -Iterations 80
}

Write-Host "[+] Compliance pack" -ForegroundColor Cyan
$date = (Get-Date).ToString('yyyy-MM-dd')
curl.exe -X POST http://localhost:8080/compliance/pack -H "Content-Type: application/json" -d '{"date":"'+$date+'"}' -o pack.zip
if(Test-Path pack.zip){ Write-Host "Pack written: pack.zip" -ForegroundColor Green }

Write-Host "[+] Grafana: http://localhost:3000 (login admin/admin)" -ForegroundColor Cyan
Write-Host "[i] Panels: Breaker State, EWMA Error, Rho, Header Bytes, Latency" -ForegroundColor DarkGray

Write-Host "[+] Done" -ForegroundColor Green
