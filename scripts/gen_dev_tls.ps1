param(
    [string]$CertPath = "src/signet/ingress/certs",
    [int]$Days = 30
)

Write-Host "Generating self-signed dev certificate (CN=localhost) valid $Days days into $CertPath"
if(!(Test-Path $CertPath)){ New-Item -ItemType Directory -Path $CertPath | Out-Null }

$certFile = Join-Path $CertPath 'dev-cert.pem'
$keyFile  = Join-Path $CertPath 'dev-key.pem'

if((Test-Path $certFile) -and (Test-Path $keyFile)){
  Write-Host "Certs already exist. Remove them to regenerate." -ForegroundColor Yellow
  return
}

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if($openssl){
  & openssl req -x509 -newkey rsa:2048 -nodes -keyout $keyFile -out $certFile -days $Days -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  Write-Host "Generated (local OpenSSL): $certFile"
} else {
  Write-Host "Local OpenSSL not found; attempting Docker-based generation" -ForegroundColor Yellow
  $abs = Resolve-Path $CertPath
  docker run --rm -v "${abs}:/work" alpine sh -c "apk add --no-cache openssl >/dev/null 2>&1 && openssl req -x509 -newkey rsa:2048 -nodes -keyout /work/dev-key.pem -out /work/dev-cert.pem -days $Days -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'" | Out-Null
  if(Test-Path $certFile){
    Write-Host "Generated (docker alpine+openssl): $certFile"
  } else {
    Write-Host "Failed to generate certs; install OpenSSL or Docker." -ForegroundColor Red
  }
}
