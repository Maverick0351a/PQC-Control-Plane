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
