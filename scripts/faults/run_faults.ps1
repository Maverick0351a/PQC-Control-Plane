param(
    [string]$BaseUrl = "https://localhost:8443",
    [int]$Iterations = 200,
    [string]$Alg = "ed25519"
)

$ErrorActionPreference = 'Stop'

function Invoke-Toxi {
    param([string]$Method='GET',[string]$Path='/proxies',[object]$Body)
    $uri = "http://localhost:8474$Path"
    $headers = @{ 'Content-Type'='application/json' }
    if($Body){
      $json = ($Body | ConvertTo-Json -Depth 5 -Compress)
      Invoke-RestMethod -Uri $uri -Method $Method -Body $json -Headers $headers
    } else {
      Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers
    }
}

Write-Host "[+] Ensuring toxiproxy proxy exists (toxiproxy:18080 -> app:8080)"
try {
  Invoke-Toxi -Method POST -Path '/proxies' -Body @{ name='app'; listen='0.0.0.0:18080'; upstream='app:8080' } | Out-Null
} catch { }

function Reset-Toxics {
  $toxics = Invoke-Toxi -Path '/proxies/app/toxics'
  foreach($t in $toxics){ Invoke-Toxi -Method DELETE -Path ("/proxies/app/toxics/" + $t.name) | Out-Null }
}

function Add-Latency([int]$LatencyMs=100,[int]$JitterMs=50){
  Invoke-Toxi -Method POST -Path '/proxies/app/toxics' -Body @{ name='latency'; type='latency'; stream='downstream'; attributes=@{ latency=$LatencyMs; jitter=$JitterMs } } | Out-Null
}
function Add-Loss([double]$LossPct=1){
  Invoke-Toxi -Method POST -Path '/proxies/app/toxics' -Body @{ name='loss'; type='limit_data'; stream='downstream'; attributes=@{ bytes_per_second=125000 } } | Out-Null
}
function Add-Bandwidth([int]$Bps=125000){ # ~1Mbps
  Invoke-Toxi -Method POST -Path '/proxies/app/toxics' -Body @{ name='bw'; type='bandwidth'; stream='downstream'; attributes=@{ rate=$Bps } } | Out-Null
}

function Metrics-Snapshot {
  try {
    $m = Invoke-RestMethod -Uri "http://localhost:8080/__metrics" -TimeoutSec 2 -ErrorAction Stop
    $route = ($m.routes | Where-Object { $_.route -eq '/protected' })
    return [pscustomobject]@{
      state = $m.breaker.state
      err   = $m.breaker.err_ewma
      rho   = $m.breaker.rho
      wq    = $m.breaker.kingman_wq_ms
      action = $m.breaker.action
    }
  } catch { return $null }
}

Write-Host "[+] Baseline traffic warmup"
for($i=0;$i -lt 20;$i++){
  try { python .\tools\pch_client_demo.py --url $BaseUrl/protected --binding tls-exporter --alg $Alg --insecure > $null 2>&1 } catch {}
  Start-Sleep -Milliseconds 100
}
$snap = Metrics-Snapshot; Write-Host "Baseline Breaker: state=$($snap.state) err=$($snap.err) rho=$($snap.rho) wq=$($snap.wq)"

$scenarios = @(
  @{ name='latency_spike'; setup={ Reset-Toxics; Add-Latency 120 60 }; desc='120ms +/-60ms'; duration=40 },
  @{ name='bandwidth_cap'; setup={ Reset-Toxics; Add-Bandwidth 64000 }; desc='~512kbps'; duration=40 },
  @{ name='combo'; setup={ Reset-Toxics; Add-Latency 150 50; Add-Bandwidth 64000 }; desc='lat+cap'; duration=40 }
)

$results = @()
foreach($sc in $scenarios){
  Write-Host "[+] Scenario: $($sc.name) ($($sc.desc))" -ForegroundColor Cyan
  & $sc.setup
  $success=0; $fail=0
  $t0 = Get-Date
  $limit = $sc.duration
  while(((Get-Date)-$t0).TotalSeconds -lt $limit){
    $out = python .\tools\pch_client_demo.py --url $BaseUrl/protected --binding tls-exporter --alg $Alg --insecure 2>&1
    if($out -match '"verified": True'){ $success++ } else { $fail++ }
    if(($success+$fail) % 5 -eq 0){
      $snap = Metrics-Snapshot
      if($snap){ Write-Host " state=$($snap.state) err=$([math]::Round($snap.err,3)) rho=$([math]::Round($snap.rho,2)) wq=$([math]::Round($snap.wq,1)) action=$($snap.action) s=$success f=$fail" }
    }
  }
  Reset-Toxics
  $snapEnd = Metrics-Snapshot
  $results += [pscustomobject]@{ scenario=$sc.name; success=$success; fail=$fail; end_state=$snapEnd.state; end_err=$snapEnd.err; end_rho=$snapEnd.rho }
  Write-Host "[+] Scenario complete: $($sc.name) successes=$success fails=$fail end_state=$($snapEnd.state)" -ForegroundColor Green
  Start-Sleep -Seconds 5
}

Write-Host "\n=== Summary ==="
$results | Format-Table -AutoSize

Write-Host "\nNOTE: Expect breaker to enter Open when err_ewma > threshold or queue Wq spikes; HalfOpen probes should recover without oscillation."
