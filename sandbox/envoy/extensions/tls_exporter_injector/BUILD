# Placeholder Bazel BUILD file for custom Envoy extension (not built in this repo).
load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_library")

envoy_cc_library(
    name = "tls_exporter_injector",
    srcs = ["filter.cc"],
    hdrs = ["filter.h"],
    deps = [
        "@envoy//source/common/common:base64",
        "@envoy//source/common/http:utility_lib",
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/ssl:connection_interface",
    ],
    repository = "@envoy",  # ensure using Envoy build context
)
