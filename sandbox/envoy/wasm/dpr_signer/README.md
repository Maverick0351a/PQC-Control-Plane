### DPR Signer WASM Filter

Features:
* Streaming SHA-384 of request & response bodies (no buffering of full payloads).
* Optional HMAC tag using a tenant pepper (config: `tenant_pepper`).
* Channel binding via exporter value already injected into a header (default `x-tls-exporter`).
* HKDF (SHA-256) derived `ekm_tag` from channel binding exporter bytes.
* JSON Canonicalized (simple stable ser) DPR record and Ed25519 signature.
* Emits response headers: `x-dpr-signature`, `x-dpr-keyid`, `x-dpr-record` (optional), `x-dpr-ekm-tag`, `x-dpr-hmac`.
* Host metrics counter: `dpr_signer.records`.

#### Build (Rust + wasm32)
```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/dpr_signer.wasm ../../dpr_signer.wasm
```

#### Envoy Config Snippet
```yaml
          - name: envoy.filters.http.wasm
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
              config:
                name: dpr_signer
                vm_config:
                  runtime: "envoy.wasm.runtime.v8"
                  code: { local: { filename: "/etc/envoy/wasm/dpr_signer.wasm" } }
                configuration:
                  @type: type.googleapis.com/google.protobuf.StringValue
                  value: |
                    {"key_id":"demo-ed25519","ed25519_secret_b64":"<base64 64B keypair bytes>","tenant_pepper":"pepper123","emit_record_header":false}
```

Note: Direct TLS exporter access is not available in proxy-wasm; upstream filter must inject exporter value.
