# Envoy TLS Exporter Injector Extension (Prototype)

This directory contains a prototype HTTP filter that injects a TLS exporter channel binding
value into each request as an HTTP header (default: `x-tls-exporter`). It is intended to
replace the Lua placeholder that synthesized a pseudo exporter.

Current status:
* The filter compiles only when Envoy adds (or you patch in) an API similar to
  `Ssl::ConnectionInfo::exportKeyingMaterial(label, context, out)` calling OpenSSL / BoringSSL
  `SSL_export_keying_material`.
* Fallback behavior uses the TLS session id base64 if exporter unavailable.

Build outline (requires full Envoy dev container / toolchain):
```bash
git clone https://github.com/envoyproxy/envoy
cd envoy
# Add this repo as a workspace overlay or copy extension sources under source/extensions/http
# Adjust BUILD to include the new target and register factory.
bazel build //source/exe:envoy-static
```

Config snippet (replace existing Lua exporter injector):
```yaml
          - name: envoy.filters.http.tls_exporter_injector
            typed_config:
              "@type": type.googleapis.com/udpa.type.v1.TypedStruct
              type_url: envoy.tls_exporter.v3.TlsExporterInjector
              value:
                context: EXPORTER-Channel-Binding
                out_header: x-tls-exporter
                length: 32
```

Roadmap:
1. Upstream PR to Envoy adding exporter API to `Ssl::ConnectionInfo`.
2. Convert this prototype into a full dynamic extension with factory registration.
3. Drop Lua placeholder and rely solely on native filter + WASM DPR signer.
