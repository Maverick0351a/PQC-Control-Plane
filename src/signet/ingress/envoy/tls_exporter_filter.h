#pragma once

#include "envoy/http/filter.h"
#include "envoy/server/filter_config.h"
#include "source/common/common/logger.h"

namespace signet {

class TlsExporterHeaderFilter : public Envoy::Http::StreamDecoderFilter, public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  Envoy::Http::FilterHeadersStatus decodeHeaders(Envoy::Http::RequestHeaderMap& headers, bool end_stream) override;
  void setDecoderFilterCallbacks(Envoy::Http::StreamDecoderFilterCallbacks& callbacks) override { callbacks_ = &callbacks; }
  Envoy::Http::FilterDataStatus decodeData(Envoy::Buffer::Instance&, bool) override { return Envoy::Http::FilterDataStatus::Continue; }
  Envoy::Http::FilterTrailersStatus decodeTrailers(Envoy::Http::RequestTrailerMap&) override { return Envoy::Http::FilterTrailersStatus::Continue; }
  void onDestroy() override {}
private:
  Envoy::Http::StreamDecoderFilterCallbacks* callbacks_{nullptr};
};

class TlsExporterHeaderFilterFactory : public Envoy::Server::Configuration::NamedHttpFilterConfigFactory {
public:
  std::string name() const override { return "signet.tls_exporter_header"; }
  Envoy::Http::FilterFactoryCb createFilterFactoryFromProto(const Envoy::Protobuf::Message&, const std::string&, Envoy::Server::Configuration::FactoryContext&) override;
  Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() override { return std::make_unique<Envoy::ProtobufWkt::Struct>(); }
};

} // namespace signet
