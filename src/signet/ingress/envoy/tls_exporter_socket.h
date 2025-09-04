#pragma once

#include "envoy/network/transport_socket.h"
#include "envoy/network/connection.h"
#include "source/common/common/logger.h"

#include <openssl/ssl.h>
#include <memory>
#include <string>

namespace signet {

// Interface key in connection filter state
static const std::string TlsExporterFilterStateKey = "signet.tls_exporter_32";

class TlsExporterSocket : public Envoy::Network::TransportSocket, public Envoy::Logger::Loggable<Envoy::Logger::Id::misc> {
public:
  TlsExporterSocket(std::unique_ptr<Envoy::Network::TransportSocket> inner);

  // TransportSocket
  void setTransportSocketCallbacks(Envoy::Network::TransportSocketCallbacks &callbacks) override;
  std::string protocol() const override { return inner_->protocol(); }
  void closeSocket(Envoy::Network::ConnectionEvent event) override { inner_->closeSocket(event); }
  Envoy::Ssl::ConnectionInfoConstSharedPtr ssl() const override { return inner_->ssl(); }
  void doHandshake() override;
  Envoy::Network::IoResult doRead(Envoy::Buffer::Instance &buffer) override { return inner_->doRead(buffer); }
  Envoy::Network::IoResult doWrite(Envoy::Buffer::Instance &buffer, bool end_stream) override { return inner_->doWrite(buffer, end_stream); }
  bool canFlushClose() override { return inner_->canFlushClose(); }
  void onConnected() override { inner_->onConnected(); }
  void rawWrite(Envoy::Buffer::Instance &buffer, bool end_stream) override { inner_->rawWrite(buffer, end_stream); }

private:
  void exportKeyingMaterial();
  bool exported_{false};
  std::unique_ptr<Envoy::Network::TransportSocket> inner_;
  Envoy::Network::TransportSocketCallbacks *callbacks_{nullptr};
};

class TlsExporterConfigFactory : public Envoy::Network::UpstreamTransportSocketConfigFactory, public Envoy::Server::Configuration::DownstreamTransportSocketConfigFactory {
public:
  std::string name() const override { return "signet.tls_exporter"; }
  // Upstream
  Envoy::Network::TransportSocketFactoryPtr createTransportSocketFactory(const Envoy::Protobuf::Message&, Envoy::Api::Api&, Envoy::Server::Configuration::TransportSocketFactoryContext&) override { return nullptr; }
  // Downstream
  Envoy::Network::TransportSocketFactoryPtr createDownstreamTransportSocketFactory(const Envoy::envoy::config::core::v3::DownstreamTransportSocketFactoryConfig&, const std::vector<Envoy::envoy::config::listener::v3::FilterChainMatch>, Envoy::Server::Configuration::TransportSocketFactoryContext&) override { return nullptr; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override { return std::make_unique<Envoy::ProtobufWkt::Struct>(); }
};

} // namespace signet
