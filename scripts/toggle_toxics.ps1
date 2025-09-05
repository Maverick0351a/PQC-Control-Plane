param(
    [string]$Proxy = 'tls_in',
    [ValidateSet('on','off')][string]$Mode = 'on'
)
# Toggle all toxics for a proxy by deleting and re-adding (simple approach)
$admin = 'http://localhost:8474'

function Get-Toxics($proxy){
    try { (Invoke-WebRequest -Uri "$admin/proxies/$proxy" -UseBasicParsing -TimeoutSec 3).Content | ConvertFrom-Json } catch { return $null }
}

$proxyState = Get-Toxics $Proxy
if(-not $proxyState){ Write-Host "Proxy $Proxy not found"; exit 1 }

if($Mode -eq 'off'){
    foreach($t in $proxyState.toxics){
        try { Invoke-WebRequest -Method Delete -Uri "$admin/proxies/$Proxy/toxics/$($t.name)" -UseBasicParsing -TimeoutSec 3 | Out-Null } catch {}
    }
    Write-Host "All toxics removed for $Proxy"
    exit 0
}

# Re-add canonical toxics set
$toxics = @(
    @{ name='latency_up'; type='latency'; stream='upstream'; attributes=@{ latency=50; jitter=10 } },
    @{ name='slice_up'; type='slicer'; stream='upstream'; attributes=@{ average_size=64; size_variation=32; delay=5 } },
    @{ name='timeout_up'; type='timeout'; stream='upstream'; attributes=@{ timeout=2000 } },
    @{ name='latency_down'; type='latency'; stream='downstream'; attributes=@{ latency=50; jitter=10 } },
    @{ name='bw_down'; type='bandwidth'; stream='downstream'; attributes=@{ rate=256 } }
)

foreach($t in $toxics){
    $body = $t | ConvertTo-Json -Compress
    try {
        Invoke-WebRequest -Method Post -Uri "$admin/proxies/$Proxy/toxics" -ContentType 'application/json' -Body $body -UseBasicParsing -TimeoutSec 3 | Out-Null
        Write-Host "Added $($t.name)"
    } catch {
        Write-Host "Failed $($t.name): $($_.Exception.Message)"
    }
}
Write-Host "Toxics applied for $Proxy (mode=$Mode)"
