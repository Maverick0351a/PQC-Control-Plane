# Minimal Envoy build using official image; custom filter would normally require WASM or C++.
# For MVP we simulate tls-exporter by reusing the TLS session (not real exporter due to complexity)
# Placeholder: In production build a WASM HTTP filter that computes RFC 9266 exporter secret.
FROM envoyproxy/envoy:v1.31-latest
COPY envoy.yaml /etc/envoy/envoy.yaml
