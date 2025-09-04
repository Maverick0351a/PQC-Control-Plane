<#
e2e_pch.ps1 — Run a single PCH-Lite round trip against the local server.

Steps:
 1. Start uvicorn on port 8080.
 2. Wait for health endpoint.
 3. GET /protected (expect 401 + PCH-Challenge header).
 4. POST /protected using demo client (expect verified True).
 5. Stop server.

Exit code 0 on success, 1 on failure.
#>
param(
  [string]$Port = '8080'
)

$ErrorActionPreference = 'Stop'
Write-Host '--- PCH Round Trip Start ---'

if(-not (Test-Path .venv/Scripts/python.exe)) { Write-Error 'Python venv not found (.venv)'; exit 1 }
$python = '.venv/Scripts/python.exe'

Write-Host 'Starting server...'
$p = Start-Process -FilePath $python -ArgumentList '-m','uvicorn','src.signet.app:app','--port', $Port -PassThru

# Wait for health (max 10s)
$healthy = $false
for($i=0; $i -lt 20; $i++) {
  try {
    $h = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/__health" -TimeoutSec 2 -UseBasicParsing
    if($h.StatusCode -eq 200){ $healthy = $true; break }
  } catch {}
  Start-Sleep -Milliseconds 500
}
if(-not $healthy){ Write-Error 'Server failed to become healthy'; Stop-Process -Id $p.Id -Force; exit 1 }
Write-Host 'Health OK'

# Challenge
$headers = @{ 'X-TLS-Session-ID' = 'devsession' }
try { $r1 = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/protected" -Headers $headers -Method GET -UseBasicParsing } catch { $r1=$_.Exception.Response }
if($r1.StatusCode -ne 401){ Write-Error "Expected 401 challenge, got $($r1.StatusCode)"; Stop-Process -Id $p.Id -Force; exit 1 }
$challenge = $r1.Headers['PCH-Challenge']
Write-Host "Challenge: $challenge"
if(-not $challenge){ Write-Error 'Missing PCH-Challenge header'; Stop-Process -Id $p.Id -Force; exit 1 }

# Signed POST via demo client
Write-Host 'Running client demo...'
$clientOut = & $python tools/pch_client_demo.py --url "http://127.0.0.1:$Port/protected" 2>&1
$clientOut | ForEach-Object { Write-Host $_ }
# Join lines for pattern search (PowerShell -match on array checks each element separately)
$clientText = ($clientOut -join "`n")
if($clientText -notmatch "'verified': True" -and $clientText -notmatch '"verified"\s*:\s*true') {
  Write-Error 'PCH verification failed (no verified True)'; Stop-Process -Id $p.Id -Force; exit 1 }

Write-Host 'Round trip success.'
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Write-Host 'Server stopped.'
Write-Host '--- DONE ---'
exit 0
