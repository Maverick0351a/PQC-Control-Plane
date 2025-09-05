#include "filter.h"

#include "envoy/server/filter_config.h"
#include "envoy/http/filter.h"

#include "source/common/protobuf/utility.h"

#include "google/protobuf/empty.pb.h"

namespace signet {

// Simple named factory with empty config (future: proto message for advanced options)
class TlsExporterInjectorFilterFactory : public Envoy::Server::Configuration::NamedHttpFilterConfigFactory {
public:
  // Create filter from empty config
  Envoy::Http::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message& /*proto_config*/, const Envoy::Server::Configuration::FactoryContext& /*context*/) override {
    ExporterConfig cfg; // defaults
    return [cfg](Envoy::Http::FilterChainFactoryCallbacks& callbacks) -> void {
      callbacks.addStreamDecoderFilter(std::make_shared<TlsExporterInjectorFilter>(cfg));
    };
  }

  // Legacy v1 JSON -> proto translation (unused, rely on empty proto)
  Envoy::Http::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message& proto_config, Envoy::Server::Configuration::FactoryContext& context, const std::string&) override {
    return createFilterFactoryFromProto(proto_config, context);
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<google::protobuf::Empty>();
  }

  std::string name() const override { return "signet.tls_exporter_injector"; }
};

// Static registration
static Envoy::Registry::RegisterFactory<TlsExporterInjectorFilterFactory, Envoy::Server::Configuration::NamedHttpFilterConfigFactory> reg_;

} // namespace signet
