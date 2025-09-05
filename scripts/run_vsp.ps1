Param(
  [string]$Scenario = ".\scenarios\sample-chaos.yaml"
)

# Ensure module path resolves local 'src' package layout
$env:PYTHONPATH = "src"

Write-Host "[vsp] Running scenario: $Scenario" -ForegroundColor Cyan
python -m signet.vsp.cli $Scenario

if ($LASTEXITCODE -ne 0) {
  Write-Error "VSP run failed with exit code $LASTEXITCODE"
  exit $LASTEXITCODE
}
