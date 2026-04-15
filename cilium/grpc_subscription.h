#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/ssl/context_manager.h"
#include "envoy/stats/scope.h"

namespace Envoy {
namespace Cilium {

// Cilium XDS API config source. Used for all Cilium XDS.
extern envoy::config::core::v3::ConfigSource cilium_xds_api_config;

std::unique_ptr<Config::Subscription>
subscribe(const std::string& type_url, Server::Configuration::CommonFactoryContext& context,
          Stats::Scope& scope, Config::SubscriptionCallbacks& callbacks,
          Config::OpaqueResourceDecoderSharedPtr resource_decoder, bool use_delta_xds = false,
          std::chrono::milliseconds init_fetch_timeout = std::chrono::milliseconds(0),
          std::function<void()> on_transport_established = {},
          std::function<void()> on_transport_close = {});

// Returns a monotonic stream generation for Cilium subscriptions.
// Value 0 is reserved for policy-map detection of the initial stream and may be returned for
// tracked gRPC subscriptions before any stream has been established.
// Non-gRPC subscriptions and subscriptions without stream tracking are treated as generation 1.
uint64_t grpcStreamGeneration(Config::Subscription* subscription);

// Returns whether a tracked gRPC subscription currently has an established transport.
bool grpcStreamConnected(Config::Subscription* subscription);

} // namespace Cilium
} // namespace Envoy
