Param(
  [string]$Url = 'https://localhost:8443/protected',
  [switch]$Insecure
)
# Simple end-to-end TLS exporter binding validation through Envoy
Write-Host '--- Bringing up redis, app, envoy (rebuild) ---'
docker compose up -d --build redis app envoy | Out-Null

# Wait for app health (through envoy not required yet)
$deadline = (Get-Date).AddSeconds(20)
do {
  try { $h = Invoke-WebRequest -UseBasicParsing -Uri http://localhost:8080/__health -TimeoutSec 2; if($h.StatusCode -eq 200){ break } } catch {}
  Start-Sleep -Milliseconds 500
} while((Get-Date) -lt $deadline)

Write-Host '--- Challenge via Envoy ---'
$curlArgs = @('-k','-I',$Url)
if(-not $Insecure){ $curlArgs = @('-I',$Url) }
$challenge = & curl.exe @curlArgs 2>$null
$challengeLines = $challenge -split "`r?`n"
$challengeLine = $challengeLines | Where-Object { $_ -match 'PCH-Challenge' }
Write-Host $challengeLine

Write-Host '--- Client demo (tls-exporter) ---'
$clientCmd = @('.venv\Scripts\python.exe','tools\pch_client_demo.py','--url',$Url,'--binding','tls-exporter','--insecure')
if(-not $Insecure){ $clientCmd = @('.venv\Scripts\python.exe','tools\pch_client_demo.py','--url',$Url,'--binding','tls-exporter') }
& $clientCmd

Write-Host '--- Metrics snapshot ---'
$metrics = Invoke-WebRequest -UseBasicParsing -Uri https://localhost:8443/__metrics -TimeoutSec 5 -SkipCertificateCheck
($metrics.Content | ConvertFrom-Json).routes | Where-Object { $_.route -eq '/protected' } | ConvertTo-Json -Depth 5

Write-Host 'Done.'
