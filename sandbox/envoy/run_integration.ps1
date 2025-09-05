Param(
  [string]$Url = 'https://localhost:8443/protected',
  [switch]$Insecure
)
Write-Host "[+] Starting integration check against $Url" -ForegroundColor Cyan

$env:FEATURE_PCH = "true"
$env:BINDING_TYPE = "tls-exporter"

function Invoke-Req {
  param([string]$u)
  try { Invoke-WebRequest -Uri $u -UseBasicParsing -Headers @{ 'X-TLS-Session-ID'='devsession' } -ErrorAction Stop }
  catch { return $null }
}

Write-Host "[+] Challenge..."; $c = Invoke-Req $Url; if(-not $c){ Write-Host 'Challenge failed' -Foreground Red; exit 1 }
$chal = $c.Headers['PCH-Challenge']
Write-Host "    Challenge: $chal"

Write-Host "[+] Verify downstream x-tls-exporter header injection via Envoy admin (expect present in DPR signer output on subsequent request)";
# We can't directly read header from previous request with PowerShell easily without full capture; rely on subsequent DPR response header presence.

Write-Host "[+] Signed bad request to force DPR emission (will 401)";
$sig='BADSIG'; $body='{}'
$headers = @{
  'content-digest'='sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:';
  'content-type'='application/json';
  'pch-challenge'=$chal;
  'pch-channel-binding'='tls-exporter=:ZGV2c2Vzc2lvbg==:';
  'x-tls-session-id'='devsession';
  'signature-input'='pch=("@method" "@path");created=0;keyid="caller-1";alg="ed25519"';
  'signature'="pch=:$sig:";
}
$r2 = Invoke-WebRequest -Uri $Url -Method POST -Body $body -Headers $headers -UseBasicParsing -ErrorAction SilentlyContinue
if($r2){
  Write-Host ("Status: {0}" -f $r2.StatusCode)
  Write-Host ("DPR Headers: signature={0} ekm={1} exporter_injected? (downstream can't show directly)" -f $r2.Headers['x-dpr-signature'],$r2.Headers['x-dpr-ekm-tag'])
} else { Write-Host 'Second request failed' -ForegroundColor Red }

Write-Host "[+] Done." -ForegroundColor Green
