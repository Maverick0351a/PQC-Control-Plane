Param()
$ErrorActionPreference = 'Stop'
$base = 'http://localhost:8474'

function New-JsonBody($obj){ $obj | ConvertTo-Json -Compress }

Write-Host 'Creating proxy tls_in (0.0.0.0:9443 -> nginx:8443)...'
$proxyBody = New-JsonBody @{ name='tls_in'; listen='0.0.0.0:9443'; upstream='nginx:8443'; enabled=$true }
try {
  Invoke-RestMethod -Method Post -Uri "$base/proxies" -ContentType 'application/json' -Body $proxyBody | Out-Null
  Write-Host 'Proxy created.'
} catch {
  Write-Warning "Proxy create failed: $($_.Exception.Message)"
}

$toxics = @(
  @{ name='latency_up'; type='latency'; stream='upstream'; toxicity=1.0; attributes=@{ latency=50; jitter=10 } },
  @{ name='latency_down'; type='latency'; stream='downstream'; toxicity=1.0; attributes=@{ latency=50; jitter=10 } },
  @{ name='bw_down'; type='bandwidth'; stream='downstream'; attributes=@{ rate=256 } },
  @{ name='slice_up'; type='slicer'; stream='upstream'; attributes=@{ average_size=200; size_variation=50; delay=10 } },
  @{ name='timeout_up'; type='timeout'; stream='upstream'; attributes=@{ timeout=2000 } }
)

foreach($t in $toxics){
  $body = New-JsonBody $t
  try {
    Invoke-RestMethod -Method Post -Uri "$base/proxies/tls_in/toxics" -ContentType 'application/json' -Body $body | Out-Null
    Write-Host "Added toxic $($t.name)"
  } catch {
    Write-Warning "Add toxic failed $($t.name): $($_.Exception.Message)"
  }
}

Write-Host 'Final proxy configuration:'
try {
  $cfg = Invoke-RestMethod -Method Get -Uri "$base/proxies/tls_in"
  $cfg | ConvertTo-Json -Depth 6
} catch {
  Write-Warning "Fetch config failed: $($_.Exception.Message)"
}
