#include "filter.h"

#include "source/common/common/base64.h"

// NOTE: This relies on a (future) upstream Envoy addition exposing SSL_export_keying_material
// via Ssl::ConnectionInfo::exportKeyingMaterial(label, context, out). For now we shim by
// returning session id if exporter not available to retain previous behavior.

namespace signet {

Envoy::Http::FilterHeadersStatus TlsExporterInjectorFilter::decodeHeaders(Envoy::Http::RequestHeaderMap& headers, bool) {
  injectExporter(headers);
  return Envoy::Http::FilterHeadersStatus::Continue;
}

void TlsExporterInjectorFilter::injectExporter(Envoy::Http::RequestHeaderMap& headers) {
  if (!callbacks_ || !callbacks_->connection()) return;
  auto ssl_info = callbacks_->connection()->ssl();
  if (!ssl_info) return; // not TLS
  std::string binding_b64;
  // Pseudo-code: awaiting API addition
  // std::vector<uint8_t> ekm(cfg_.length);
  // if (ssl_info->exportKeyingMaterial(cfg_.context, absl::string_view(), ekm)) {
  //     binding_b64 = Envoy::Base64::encode(ekm.data(), ekm.size());
  // }
  // Fallback: session id hash (legacy behavior placeholder)
  if (binding_b64.empty()) {
    const auto& sid = ssl_info->sessionId();
    if (!sid.empty()) {
      binding_b64 = Envoy::Base64::encode(sid.data(), sid.size());
    }
  }
  if (!binding_b64.empty()) {
    headers.addCopy(Envoy::Http::LowerCaseString(cfg_.out_header), binding_b64);
  }
}

} // namespace signet
