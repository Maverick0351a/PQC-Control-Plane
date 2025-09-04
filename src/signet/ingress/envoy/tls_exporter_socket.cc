#include "tls_exporter_socket.h"

#include "envoy/network/connection.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/common/common/base64.h"

namespace signet {

TlsExporterSocket::TlsExporterSocket(std::unique_ptr<Envoy::Network::TransportSocket> inner)
  : inner_(std::move(inner)) {}

void TlsExporterSocket::setTransportSocketCallbacks(Envoy::Network::TransportSocketCallbacks &callbacks) {
  callbacks_ = &callbacks;
  inner_->setTransportSocketCallbacks(callbacks);
}

void TlsExporterSocket::doHandshake() {
  inner_->doHandshake();
  if (!exported_) {
    exportKeyingMaterial();
  }
}

void TlsExporterSocket::exportKeyingMaterial() {
  if (exported_) { return; }
  auto ssl_info = inner_->ssl();
  if (!ssl_info) { return; }
  SSL* ssl = const_cast<SSL*>(ssl_info->ssl());
  if (!ssl) { return; }
  unsigned char out[32];
  const char* label = "EXPORTER-Channel-Binding";
  if (SSL_export_keying_material(ssl, out, sizeof(out), label, strlen(label), nullptr, 0, 0) == 1) {
    std::string b64 = Envoy::Base64::encode(out, sizeof(out));
    // Store in filter state (read-only once set)
    callbacks_->connection().streamInfo().filterState()->setData(
      TlsExporterFilterStateKey,
      std::make_shared<Envoy::StreamInfo::StringAccessorImpl>(b64),
      Envoy::StreamInfo::FilterState::StateType::ReadOnly,
      Envoy::StreamInfo::FilterState::LifeSpan::Connection
    );
    ENVOY_LOG(info, "Exported 32-byte TLS exporter (b64 length={}): {}", b64.size(), b64.substr(0,8));
    exported_ = true;
  }
}

} // namespace signet
