Param(
  [string]$ImageRef = "signet-pqc:latest",
  [string]$SbomOut = "sbom.json",
  [string]$ProvenanceOut = "provenance.json"
)

Write-Host "[SBOM] Generating CycloneDX SBOM from requirements.txt"
if(-not (Test-Path requirements.txt)){ Write-Error "requirements.txt not found"; exit 1 }

# CycloneDX for Python deps
$env:CYCLONEDX_PYTHON_REQUIREMENTS_SKIP_ERRORS="true"
try {
  python -m cyclonedx_bom -o $SbomOut -F json
  Write-Host "[SBOM] Wrote $SbomOut"
} catch {
  Write-Error "CycloneDX generation failed: $_"; exit 1
}

# Minimal provenance (SLSA inspired) – NOT a full SLSA attestation
$prov = [ordered]@{
  _type = "https://in-toto.io/Statement/v0.1"
  subject = @(@{ name = $ImageRef; digest = @{ sha256 = (Get-FileHash -Algorithm SHA256 Dockerfile).Hash }})
  predicateType = "https://slsa.dev/provenance/v0.2"
  predicate = @{ builder = @{ id = "local-dev" }; buildType = "dockerfile"; invocation = @{ configSource = @{ uri = "./Dockerfile" } } }
}
$prov | ConvertTo-Json -Depth 6 | Out-File $ProvenanceOut -Encoding utf8
Write-Host "[PROVENANCE] Wrote $ProvenanceOut"

Write-Host "Done. Optionally sign artifacts with: cosign sign --key cosign.key $ImageRef"
