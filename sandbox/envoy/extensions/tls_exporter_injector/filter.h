#pragma once

#include "envoy/http/filter.h"
#include "envoy/network/connection.h"
#include "envoy/ssl/connection.h"

#include <string>

namespace signet {

struct ExporterConfig {
  std::string context = "EXPORTER-Channel-Binding"; // label used in exporter
  std::string out_header = "x-tls-exporter";        // header to inject
  uint32_t length = 32;                              // output length bytes
};

class TlsExporterInjectorFilter : public Envoy::Http::StreamDecoderFilter {
public:
  TlsExporterInjectorFilter(const ExporterConfig& cfg) : cfg_(cfg) {}

  // Http::StreamDecoderFilter
  Envoy::Http::FilterHeadersStatus decodeHeaders(Envoy::Http::RequestHeaderMap& headers, bool end_stream) override;
  void setDecoderFilterCallbacks(Envoy::Http::StreamDecoderFilterCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }
  Envoy::Http::FilterDataStatus decodeData(Envoy::Buffer::Instance&, bool) override { return Envoy::Http::FilterDataStatus::Continue; }
  Envoy::Http::FilterTrailersStatus decodeTrailers(Envoy::Http::RequestTrailerMap&) override { return Envoy::Http::FilterTrailersStatus::Continue; }
  void onDestroy() override {}

private:
  ExporterConfig cfg_;
  Envoy::Http::StreamDecoderFilterCallbacks* callbacks_{};
  void injectExporter(Envoy::Http::RequestHeaderMap& headers);
};

} // namespace signet
