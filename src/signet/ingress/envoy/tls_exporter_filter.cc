#include "tls_exporter_filter.h"
#include "tls_exporter_socket.h"

#include "envoy/stream_info/filter_state.h"
#include "source/common/common/base64.h"

namespace signet {

Envoy::Http::FilterHeadersStatus TlsExporterHeaderFilter::decodeHeaders(Envoy::Http::RequestHeaderMap& headers, bool) {
  auto* fs = callbacks_->streamInfo().filterState().getDataReadOnly<Envoy::StreamInfo::StringAccessor>(TlsExporterFilterStateKey);
  if (fs) {
    std::string b64 = fs->asString();
    std::string header_value = "tls-exporter=:" + b64 + ":";
    headers.addCopy(Envoy::Http::LowerCaseString("pch-channel-binding"), header_value);
    // Internal header for debugging (will be stripped later if needed)
    headers.addCopy(Envoy::Http::LowerCaseString("x-internal-tls-exporter"), b64);
  }
  return Envoy::Http::FilterHeadersStatus::Continue;
}

Envoy::Http::FilterFactoryCb TlsExporterHeaderFilterFactory::createFilterFactoryFromProto(const Envoy::Protobuf::Message&, const std::string&, Envoy::Server::Configuration::FactoryContext&) {
  return [](Envoy::Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<TlsExporterHeaderFilter>());
  };
}

} // namespace signet
