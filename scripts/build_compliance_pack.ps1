<#
build_compliance_pack.ps1 — Generate and verify a compliance pack for today.

Prereq: Run at least one (preferably multiple) PCH round trips to emit receipts.

Steps:
 1. Start server (if not already) OR reuse existing with -Reuse.
 2. Perform two signed round trips (emits receipts).
 3. Call /compliance/pack for today's date.
 4. Unzip pack to tmp_pack/.
 5. Run offline verifier (expect OK).
 6. Stop server unless -Reuse supplied.

Exit code 0 if verification OK, else 1.
#>
param(
  [string]$Port = '8080',
  [switch]$Reuse
)

$ErrorActionPreference = 'Stop'
$python = '.venv/Scripts/python.exe'
if(-not (Test-Path $python)) { Write-Error 'Missing .venv. Create venv and install requirements first.'; exit 1 }

$startedHere = $false
if(-not $Reuse) {
  Write-Host 'Starting server...'
  $p = Start-Process -FilePath $python -ArgumentList '-m','uvicorn','src.signet.app:app','--port', $Port -PassThru
  $startedHere = $true
  # Wait for health
  for($i=0;$i -lt 20;$i++){ try { $h=Invoke-WebRequest -Uri "http://127.0.0.1:$Port/__health" -TimeoutSec 2 -UseBasicParsing; if($h.StatusCode -eq 200){ break } } catch {}; Start-Sleep -Milliseconds 500 }
}

function Invoke-PCHTrip {
  param([string]$Url)
  & $python tools/pch_client_demo.py --url $Url 2>&1
}

Write-Host 'Executing two PCH round trips...'
$out1 = Invoke-PCHTrip -Url "http://127.0.0.1:$Port/protected"
$out1 | ForEach-Object { Write-Host "CLIENT1: $_" }
$out1Text = ($out1 -join "`n")
$out2 = Invoke-PCHTrip -Url "http://127.0.0.1:$Port/protected"
$out2 | ForEach-Object { Write-Host "CLIENT2: $_" }
$out2Text = ($out2 -join "`n")
if($out2Text -notmatch "'verified': True" -and $out2Text -notmatch '"verified"\s*:\s*true') { Write-Warning 'Second trip not verified; proceeding but receipts may be incomplete.' }

$today = (Get-Date -Format 'yyyy-MM-dd')
Write-Host "Building compliance pack for $today"
$body = @{ date = $today } | ConvertTo-Json -Compress
$packResp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/compliance/pack" -Method POST -Body $body -ContentType 'application/json' -UseBasicParsing
$packJson = $packResp.Content
Write-Host "PACK_RESPONSE=$packJson"
$packPath = (ConvertFrom-Json $packJson).pack
if(-not (Test-Path $packPath)) { Write-Error "Pack path not found: $packPath"; if($startedHere){ Stop-Process -Id $p.Id -Force }; exit 1 }

if(Test-Path tmp_pack){ Remove-Item -Recurse -Force tmp_pack }
Expand-Archive -Path $packPath -DestinationPath tmp_pack -Force
Write-Host 'Pack extracted to tmp_pack/'

Write-Host 'Running offline verifier...'
$verifyOut = & $python tmp_pack/verify_cli.py tmp_pack/sth.json tmp_pack/receipts.jsonl tmp_pack/proofs 2>&1
$verifyOut | ForEach-Object { Write-Host $_ }
if($verifyOut -notmatch 'OK'){ Write-Error 'Compliance verification FAILED'; if($startedHere){ Stop-Process -Id $p.Id -Force }; exit 1 }
Write-Host 'Compliance verification OK.'

if($startedHere -and -not $Reuse){ Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; Write-Host 'Server stopped.' }
exit 0
