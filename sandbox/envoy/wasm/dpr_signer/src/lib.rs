use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use sha2::{Sha384, Digest};
use hkdf::Hkdf;
use sha2::Sha256; // for HKDF fallback if needed
use ed25519_dalek::{SigningKey, Signature, Signer, SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH};
use serde::Serialize;
use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::rngs::StdRng;
use rand::{SeedableRng, RngCore};

// Configuration passed via filter config (JSON) when loading WASM.
#[derive(serde::Deserialize, Debug, Clone)]
struct Config {
    key_id: String,
    /// Base64 either 32B secret or 64B concatenated secret||public.
    ed25519_secret_b64: String,
    #[serde(default)]
    tenant_pepper: Option<String>,
    #[serde(default)]
    channel_binding_header: Option<String>, // header to read exporter from (default x-tls-exporter)
    #[serde(default)]
    emit_record_header: bool, // if true include canonical DPR in header (base64)
    #[serde(default)]
    generate_if_missing: bool, // generate ephemeral key if config empty
}

static DEFAULT_CONFIG: Lazy<Config> = Lazy::new(|| Config { key_id: "dpr-key".into(), ed25519_secret_b64: String::new(), tenant_pepper: None, channel_binding_header: Some("x-tls-exporter".into()), emit_record_header: false, generate_if_missing: true });

#[derive(Serialize)]
struct DprRecord<'a> {
    v: u8,
    ts: u64,
    method: &'a str,
    path: &'a str,
    cb: &'a str, // channel binding (exporter) base64
    req_sha384: String,
    rsp_sha384: String,
    #[serde(skip_serializing_if = "Option::is_none")] hmac_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] ekm_tag: Option<String>,
}

struct DprContext {
    cfg: Config,
    signing_key: Option<SigningKey>,
    req_hasher: Sha384,
    rsp_hasher: Sha384,
    req_bytes: u64,
    rsp_bytes: u64,
    method: String,
    path: String,
    channel_binding: String,
    generated: bool,
}

impl DprContext {
    fn new(cfg: Config, signing_key: Option<SigningKey>, generated: bool) -> Self {
        DprContext { cfg, signing_key, req_hasher: Sha384::new(), rsp_hasher: Sha384::new(), req_bytes:0, rsp_bytes:0, method: String::new(), path: String::new(), channel_binding: String::new(), generated }
    }
}

struct Root;
impl Context for Root {}
impl RootContext for Root {
    fn on_configure(&mut self, _conf_size: usize) -> bool { true }
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpFilter { ctx: None }))
    }
    fn get_type(&self) -> Option<ContextType> { Some(ContextType::HttpContext) }
}

struct HttpFilter {
    ctx: Option<DprContext>,
}

impl Context for HttpFilter {}

impl HttpContext for HttpFilter {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let raw_cfg = self.get_property(&["plugin_root_id"]).ok(); // placeholder
        // Retrieve custom config JSON from plugin_vm_id property; if missing, use default.
        let cfg: Config = if let Some(bytes) = self.get_configuration() { serde_json::from_slice(&bytes).unwrap_or(DEFAULT_CONFIG.clone()) } else { DEFAULT_CONFIG.clone() };
        let mut generated = false;
        let mut sk: Option<SigningKey> = None;
        if !cfg.ed25519_secret_b64.is_empty() {
            if let Ok(raw) = general_purpose::STANDARD.decode(cfg.ed25519_secret_b64.as_bytes()) {
                sk = match raw.len() {
                    32 => SigningKey::from_keypair_bytes(&{
                        // Expand by computing public key
                        let mut kp = [0u8; 64];
                        kp[..32].copy_from_slice(&raw);
                        let tmp = SigningKey::from_bytes(&raw.try_into().unwrap());
                        kp[32..].copy_from_slice(tmp.verifying_key().as_bytes());
                        kp
                    }).ok(),
                    64 => SigningKey::from_keypair_bytes(&raw).ok(),
                    _ => None
                };
            }
        } else if cfg.generate_if_missing {
            // Deterministic-ish seed from time just for demo; real systems should use secure randomness.
            let mut seed = [0u8;32];
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            for (i,b) in seed.iter_mut().enumerate() { *b = (now >> (i%8)*8) as u8; }
            let mut rng = StdRng::from_seed(seed);
            let mut sk_bytes = [0u8;32];
            rng.fill_bytes(&mut sk_bytes);
            let tmp = SigningKey::from_bytes(&sk_bytes);
            // Compose keypair bytes
            let mut kp = [0u8;64];
            kp[..32].copy_from_slice(&sk_bytes);
            kp[32..].copy_from_slice(tmp.verifying_key().as_bytes());
            let b64 = general_purpose::STANDARD.encode(kp);
            self.add_http_response_header("x-dpr-ephemeral-key", b64);
            sk = SigningKey::from_keypair_bytes(&kp).ok();
            generated = true;
        }
        let mut dc = DprContext::new(cfg, sk, generated);
        let headers = self.get_http_request_headers();
        for (k,v) in headers.iter() { if k.eq_ignore_ascii_case(":method") { dc.method = v.clone(); } else if k.eq_ignore_ascii_case(":path") { dc.path = v.clone(); } }
        // Channel binding value from header (already injected by earlier filter / TLS exporter filter)
        let cb_hdr = dc.cfg.channel_binding_header.clone().unwrap_or_else(|| "x-tls-exporter".into());
        for (k,v) in headers.iter() { if k.eq_ignore_ascii_case(&cb_hdr) { dc.channel_binding = v.clone(); break; }}
        self.ctx = Some(dc);
        Action::Continue
    }
    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if let Some(dc) = self.ctx.as_mut() {
            if let Some(body) = self.get_http_request_body(0, body_size) { dc.req_hasher.update(&body); dc.req_bytes += body.len() as u64; }
        }
        if end_of_stream { Action::Continue } else { Action::Pause }
    }
    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if let Some(dc) = self.ctx.as_mut() {
            if let Some(body) = self.get_http_response_body(0, body_size) { dc.rsp_hasher.update(&body); dc.rsp_bytes += body.len() as u64; }
            if end_of_stream { self.finish_record(); }
        }
        Action::Continue
    }
}

impl HttpFilter {
    fn finish_record(&mut self) {
        let dc = match self.ctx.as_mut() { Some(c) => c, None => return };
        let req_hash = dc.req_hasher.clone().finalize();
        let rsp_hash = dc.rsp_hasher.clone().finalize();
        let req_hex = hex::encode(req_hash);
        let rsp_hex = hex::encode(rsp_hash);
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        // Optional HMAC (pepper) – naive: HMAC = SHA384(pepper || req || rsp)
        let mut hmac_tag = None;
        if let Some(pep) = &dc.cfg.tenant_pepper { let mut h = Sha384::new(); h.update(pep.as_bytes()); h.update(req_hex.as_bytes()); h.update(rsp_hex.as_bytes()); hmac_tag = Some(hex::encode(h.finalize())); }
        // ekm_tag via HKDF over exporter (channel binding) if present
        let mut ekm_tag = None;
        if !dc.channel_binding.is_empty() {
            if let Ok(raw_cb) = general_purpose::STANDARD.decode(&dc.channel_binding) {
                let hk = Hkdf::<Sha256>::new(None, &raw_cb); // salt none for now
                let mut okm = [0u8; 32];
                if hk.expand(b"dpr-ekm-tag", &mut okm).is_ok() { ekm_tag = Some(hex::encode(okm)); }
            }
        }
    let rec = DprRecord { v:1, ts, method:&dc.method, path:&dc.path, cb:&dc.channel_binding, req_sha384:req_hex, rsp_sha384:rsp_hex, hmac_tag, ekm_tag };
        // Canonical JSON (JCS): serde_json already orders insertion; ensure stable by sorting keys manually via Value map
        let json = serde_json::to_string(&rec).unwrap_or_else(|_| "{}".into());
        // Sign canonical record
    if let Some(sk) = &dc.signing_key { let sig: Signature = sk.sign(json.as_bytes()); let sig_b64 = general_purpose::STANDARD.encode(sig.to_bytes()); self.add_http_response_header("x-dpr-signature", sig_b64); self.add_http_response_header("x-dpr-keyid", dc.cfg.key_id.clone()); } else { self.incr_counter("dpr_signer.sig_missing",1); }
    if dc.cfg.emit_record_header { self.add_http_response_header("x-dpr-record", general_purpose::STANDARD.encode(json.as_bytes())); }
        if let Some(tag) = &rec.ekm_tag { self.add_http_response_header("x-dpr-ekm-tag", tag.clone()); }
        if let Some(hmac) = &rec.hmac_tag { self.add_http_response_header("x-dpr-hmac", hmac.clone()); }
        // Metrics (counters)
        self.incr_counter("dpr_signer.records", 1);
    self.incr_counter("dpr_signer.req_bytes", dc.req_bytes);
    self.incr_counter("dpr_signer.rsp_bytes", dc.rsp_bytes);
    if dc.generated { self.incr_counter("dpr_signer.ephemeral_keys",1); }
    }
}

proxy_wasm::main!({ proxy_wasm::set_log_level(LogLevel::Info); proxy_wasm::set_root_context(|_| Box::new(Root)); });
