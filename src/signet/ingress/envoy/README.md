# Envoy exporter spike (strong channel binding)

**Goal:** Produce a per-connection 32-byte TLS exporter value (`tls-exporter`) with label `EXPORTER-Channel-Binding`, context `""`, length `32`, and expose it to HTTP filters (as an internal request header) for the PCH-Lite verifier. Strip before egress.

**Approach (sketch):**
- Implement a **custom transport socket or SSL extension** to call `SSL_export_keying_material()` after TLS handshake.
- Store the exporter value in Envoy's connection info so an HTTP filter can read and attach it to the request as `x-internal-tls-exporter`.
- The HTTP filter copies that into `PCH-Channel-Binding: tls-exporter=:<b64(ekm)>:` and forwards to the app.
- Do not expose exporter values outside the mesh; strip on egress.

**Why not Wasm?** Wasm HTTP filters cannot access TLS session secrets; use C++ at the transport socket layer.

**Config:** See `envoy.yaml` for a placeholder setup (no EKM extraction).

**MVP fallback:** Use `X-TLS-Session-ID` forwarded by NGINX. Not cryptographically strong; advisory only.

## Build (spike)

Requires an Envoy source checkout and toolchain. Example (conceptual):

1. Clone Envoy (matching your desired release):
	git clone https://github.com/envoyproxy/envoy.git
2. Copy the `tls_exporter_*` files and `BUILD` snippet into a custom extension directory, or add this repo as a external workspace.
3. Add to your `EXTENSIONS` or directly reference the targets:
	bazel build //src/signet/ingress/envoy:tls_exporter_socket //src/signet/ingress/envoy:tls_exporter_filter
4. Configure listener filter chain to use `signet.tls_exporter` transport socket (factory currently returns nullptr – implement wiring) and add HTTP filter:
	- name: signet.tls_exporter_header
5. On each request, header `pch-channel-binding: tls-exporter=:<b64>:` will be injected.

This is a non-functional skeleton (factory returns nullptr) intended for iterative development.
