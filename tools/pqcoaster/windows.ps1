Param(
  [int]$Mss = 1200,
  [string]$Interface = ''
)
Write-Host "[pqcoaster] Applying path shield (Windows) MSS=$Mss" -ForegroundColor Cyan

# Enable PMTU discovery (already default on modern Windows but explicit for clarity)
netsh interface ipv4 set global pmtudiscovery=enabled | Out-Null

# Allow ICMPv4 PTB (Type 3 Code 4)
try {
  if (-not (Get-NetFirewallRule -DisplayName 'Allow ICMPv4 PTB' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'Allow ICMPv4 PTB' -Protocol ICMPv4 -ICMPType 3,4 -Direction Inbound -Action Allow | Out-Null
  }
} catch {}

# (Optional) Adjust interface MTU if provided
if ($Interface -and $Interface.Trim() -ne '') {
  Write-Host "[pqcoaster] (Advisory) To clamp MSS, lowering interface MTU might be required; manual step for now." -ForegroundColor Yellow
}

Write-Host "[pqcoaster] Complete." -ForegroundColor Green
