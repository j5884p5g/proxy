#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/server/factory_context.h"
#include "envoy/stats/scope.h"

namespace Envoy {
namespace Cilium {

// Cilium XDS API config source. Used for all Cilium XDS.
extern envoy::config::core::v3::ConfigSource cilium_xds_api_config;

std::unique_ptr<Config::Subscription>
subscribe(const std::string& type_url, Server::Configuration::CommonFactoryContext& context,
          Stats::Scope& scope, Config::SubscriptionCallbacks& callbacks,
          Config::OpaqueResourceDecoderSharedPtr resource_decoder,
          std::chrono::milliseconds init_fetch_timeout = std::chrono::milliseconds(0));

// Returns a monotonic stream generation for Cilium subscriptions.
// Value 0 is reserved for policy-map detection of the initial stream and may be returned for
// tracked gRPC subscriptions before any stream has been established.
// Non-gRPC subscriptions and subscriptions without stream tracking are treated as generation 1.
uint64_t grpcStreamGeneration(Config::Subscription* subscription);

} // namespace Cilium
} // namespace Envoy
