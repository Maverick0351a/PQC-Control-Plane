load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_library")

envoy_cc_library(
    name = "tls_exporter_socket",
    srcs = ["tls_exporter_socket.cc"],
    hdrs = ["tls_exporter_socket.h"],
    deps = [
        "@envoy//source/common/network:transport_socket_interface_lib",
        "@envoy//source/extensions/transport_sockets/tls:ssl_socket_lib",
        "@envoy//source/common/common:logger_lib",
    ],
)

envoy_cc_library(
    name = "tls_exporter_filter",
    srcs = ["tls_exporter_filter.cc"],
    hdrs = ["tls_exporter_filter.h"],
    deps = [
        ":tls_exporter_socket",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/http:utility_lib",
        "@envoy//source/common/network:connection_lib",
    ],
)
