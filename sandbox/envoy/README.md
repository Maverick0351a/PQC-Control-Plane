## Integration Harness

Run `./sandbox/envoy/run_integration.ps1` after starting docker-compose to exercise:
1. Challenge issuance.
2. TLS exporter injector (native prototype) → exporter consumed by WASM DPR signer (ekm_tag present).
3. DPR signing headers.

If `X-DPR-EKM-Tag` is present on response the channel binding path worked (exporter header existed).

# Envoy TLS Exporter Sandbox

This sandbox would provide a real RFC 9266 TLS exporter header `x-tls-exporter` used for channel binding.

MVP note: Actual TLS exporter computation requires custom C++ or WASM filter with access to SSL connection secrets; here the implementation is a placeholder and must be replaced with a production-grade filter.

## Build & Run

```powershell
# Build sandbox image
cd sandbox/envoy
docker build -t signet-envoy .
# Launch via compose (preferred)
# docker compose up -d envoy
```

Hit endpoint:
```powershell
curl.exe -k https://localhost:8443/echo/headers
```

You should observe an `x-tls-exporter` header (placeholder value in this MVP) forwarded to the upstream app.

## Via docker compose

```powershell
docker compose up -d --build envoy app
curl.exe -k https://localhost:8444/echo/headers
```

Expect roughly a 44-character base64 string for `x-tls-exporter`.

> NOTE: This is a pseudo exporter (hash of session id) and NOT a compliant RFC 9266 implementation. Replace the Lua filter with a proper WASM or compiled filter that calls the underlying TLS library exporter API for production.
