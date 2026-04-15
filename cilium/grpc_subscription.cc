#include "cilium/grpc_subscription.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/annotations/resource.pb.h"
#include "envoy/common/exception.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/custom_config_validators.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/subscription.h"
#include "envoy/config/subscription_factory.h"
#include "envoy/grpc/async_client.h"
#include "envoy/server/factory_context.h"
#include "envoy/stats/scope.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/assert.h"
#include "source/common/common/backoff_strategy.h"
#include "source/common/config/utility.h"
#include "source/common/grpc/common.h"
#include "source/common/protobuf/protobuf.h" // IWYU pragma: keep
#include "source/extensions/config_subscription/grpc/grpc_mux_context.h"
#include "source/extensions/config_subscription/grpc/grpc_mux_impl.h"
#include "source/extensions/config_subscription/grpc/grpc_subscription_impl.h"
#include "source/extensions/config_subscription/grpc/new_grpc_mux_impl.h"

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

namespace Envoy {
namespace Cilium {

namespace {

constexpr uint64_t FirstStreamGeneration = 1;

class StreamTrackedGrpcMux {
public:
  virtual ~StreamTrackedGrpcMux() = default;
  virtual uint64_t streamGeneration() const = 0;
  virtual bool streamConnected() const = 0;
};

class SotwGrpcMuxImpl : public Config::GrpcMuxImpl, public StreamTrackedGrpcMux {
public:
  SotwGrpcMuxImpl(Config::GrpcMuxContext& grpc_mux_context, bool skip_subsequent_node,
                  std::function<void()> on_transport_established,
                  std::function<void()> on_transport_close)
      : Config::GrpcMuxImpl(grpc_mux_context, skip_subsequent_node),
        on_transport_established_(std::move(on_transport_established)),
        on_transport_close_(std::move(on_transport_close)) {}

  ~SotwGrpcMuxImpl() override = default;

  void onStreamEstablished() override {
    stream_connected_ = true;
    ++stream_generation_;
    Config::GrpcMuxImpl::onStreamEstablished();
    if (on_transport_established_) {
      on_transport_established_();
    }
  }

  void onEstablishmentFailure(bool next_attempt_may_send_initial_resource_version) override {
    const bool was_connected = stream_connected_;
    stream_connected_ = false;
    Config::GrpcMuxImpl::onEstablishmentFailure(next_attempt_may_send_initial_resource_version);
    if (was_connected && on_transport_close_) {
      on_transport_close_();
    }
  }

  uint64_t streamGeneration() const override { return stream_generation_; }
  bool streamConnected() const override { return stream_connected_; }

private:
  uint64_t stream_generation_{0};
  bool stream_connected_{false};
  std::function<void()> on_transport_established_;
  std::function<void()> on_transport_close_;
};

class DeltaGrpcMuxImpl : public Config::NewGrpcMuxImpl, public StreamTrackedGrpcMux {
public:
  explicit DeltaGrpcMuxImpl(Config::GrpcMuxContext& grpc_mux_context,
                            std::function<void()> on_transport_established,
                            std::function<void()> on_transport_close)
      : Config::NewGrpcMuxImpl(grpc_mux_context),
        on_transport_established_(std::move(on_transport_established)),
        on_transport_close_(std::move(on_transport_close)) {}

  ~DeltaGrpcMuxImpl() override = default;

  void onStreamEstablished() override {
    stream_connected_ = true;
    ++stream_generation_;
    Config::NewGrpcMuxImpl::onStreamEstablished();
    if (on_transport_established_) {
      on_transport_established_();
    }
  }

  void onEstablishmentFailure(bool next_attempt_may_send_initial_resource_version) override {
    const bool was_connected = stream_connected_;
    stream_connected_ = false;
    Config::NewGrpcMuxImpl::onEstablishmentFailure(next_attempt_may_send_initial_resource_version);
    if (was_connected && on_transport_close_) {
      on_transport_close_();
    }
  }

  uint64_t streamGeneration() const override { return stream_generation_; }
  bool streamConnected() const override { return stream_connected_; }

private:
  uint64_t stream_generation_{0};
  bool stream_connected_{false};
  std::function<void()> on_transport_established_;
  std::function<void()> on_transport_close_;
};

// service RPC method fully qualified names.
struct Service {
  std::string sotw_grpc_method_;
  std::string delta_grpc_method_;
  std::string rest_method_;
};

// Map from resource type URL to service RPC methods.
using TypeUrlToServiceMap = absl::flat_hash_map<std::string, Service>;

TypeUrlToServiceMap* buildTypeUrlToServiceMap() {
  auto* type_url_to_service_map = new TypeUrlToServiceMap();
  // This happens once in the lifetime of Envoy. We build a reverse map from
  // resource type URL to service methods. We explicitly enumerate all services,
  // since DescriptorPool doesn't support iterating over all descriptors, due
  // its lazy load design, see
  // https://www.mail-archive.com/protobuf@googlegroups.com/msg04540.html.
  for (absl::string_view name : {
           "cilium.NetworkPolicyDiscoveryService",
           "cilium.NetworkPolicyResourceDiscoveryService",
           "cilium.NetworkPolicyHostsDiscoveryService",
       }) {
    const auto* service_desc =
        Protobuf::DescriptorPool::generated_pool()->FindServiceByName(std::string(name));
    // TODO(htuch): this should become an ASSERT once all v3 descriptors are
    // linked in.
    ASSERT(service_desc != nullptr, fmt::format("{} missing", name));
    ASSERT(service_desc->options().HasExtension(envoy::annotations::resource));
    const std::string resource_type_url = Grpc::Common::typeUrl(
        service_desc->options().GetExtension(envoy::annotations::resource).type());
    Service& service = (*type_url_to_service_map)[resource_type_url];
    // We populate the service methods that are known below, but it's possible
    // that some services don't implement all, e.g. VHDS doesn't support SotW or
    // REST.
    for (int method_index = 0; method_index < service_desc->method_count(); ++method_index) {
      const auto& method_desc = *service_desc->method(method_index);
      if (absl::StartsWith(method_desc.name(), "Stream")) {
        service.sotw_grpc_method_ = method_desc.full_name();
      } else if (absl::StartsWith(method_desc.name(), "Delta")) {
        service.delta_grpc_method_ = method_desc.full_name();
      } else if (absl::StartsWith(method_desc.name(), "Fetch")) {
        service.rest_method_ = method_desc.full_name();
      } else {
        ASSERT(false, "Unknown xDS service method");
      }
    }
  }
  return type_url_to_service_map;
}

TypeUrlToServiceMap& typeUrlToServiceMap() {
  static TypeUrlToServiceMap* type_url_to_service_map = buildTypeUrlToServiceMap();
  return *type_url_to_service_map;
}

class NopConfigValidatorsImpl : public Envoy::Config::CustomConfigValidators {
public:
  NopConfigValidatorsImpl() = default;

  void executeValidators(absl::string_view,
                         const std::vector<Envoy::Config::DecodedResourcePtr>&) override {}
  void executeValidators(absl::string_view, const std::vector<Envoy::Config::DecodedResourcePtr>&,
                         const Protobuf::RepeatedPtrField<std::string>&) override {}
};

} // namespace

const Protobuf::MethodDescriptor& deltaGrpcMethod(absl::string_view type_url) {
  const auto it = typeUrlToServiceMap().find(static_cast<std::string>(type_url));
  ASSERT(it != typeUrlToServiceMap().cend());
  return *Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
      it->second.delta_grpc_method_);
}

const Protobuf::MethodDescriptor& sotwGrpcMethod(absl::string_view type_url) {
  const auto it = typeUrlToServiceMap().find(static_cast<std::string>(type_url));
  ASSERT(it != typeUrlToServiceMap().cend());
  return *Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
      it->second.sotw_grpc_method_);
}

// Hard-coded Cilium gRPC cluster
// Note: No rate-limit settings are used, consider if needed.
envoy::config::core::v3::ConfigSource getCiliumXDSAPIConfig(bool use_delta_xds = false) {
  auto config_source = envoy::config::core::v3::ConfigSource();
  /* config_source.initial_fetch_timeout is set to 50 milliseconds.
   * This applies only to SDS Secrets for now, as for NPDS and NPHDS we explicitly set the timeout
   * as 0 (no timeout).
   */
  config_source.mutable_initial_fetch_timeout()->set_nanos(50000000);
  config_source.set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
  auto api_config_source = config_source.mutable_api_config_source();
  api_config_source->set_set_node_on_first_message_only(true);
  api_config_source->set_api_type(use_delta_xds
                                      ? envoy::config::core::v3::ApiConfigSource::DELTA_GRPC
                                      : envoy::config::core::v3::ApiConfigSource::GRPC);
  api_config_source->set_transport_api_version(envoy::config::core::v3::ApiVersion::V3);
  api_config_source->add_grpc_services()->mutable_envoy_grpc()->set_cluster_name("xds-grpc-cilium");
  return config_source;
}

envoy::config::core::v3::ConfigSource cilium_xds_api_config = getCiliumXDSAPIConfig();

uint64_t grpcStreamGeneration(Config::Subscription* subscription) {
  auto* sub = dynamic_cast<Config::GrpcSubscriptionImpl*>(subscription);
  if (!sub) {
    return FirstStreamGeneration;
  }

  auto* grpc_mux = dynamic_cast<StreamTrackedGrpcMux*>(sub->grpcMux().get());
  if (grpc_mux == nullptr) {
    return FirstStreamGeneration;
  }

  return grpc_mux->streamGeneration();
}

bool grpcStreamConnected(Config::Subscription* subscription) {
  auto* sub = dynamic_cast<Config::GrpcSubscriptionImpl*>(subscription);
  if (!sub) {
    return false;
  }

  auto* grpc_mux = dynamic_cast<StreamTrackedGrpcMux*>(sub->grpcMux().get());
  if (grpc_mux == nullptr) {
    return false;
  }

  return grpc_mux->streamConnected();
}

std::unique_ptr<Config::Subscription>
subscribe(const std::string& type_url, Server::Configuration::CommonFactoryContext& context,
          Stats::Scope& scope, Config::SubscriptionCallbacks& callbacks,
          Config::OpaqueResourceDecoderSharedPtr resource_decoder, bool use_delta_xds,
          std::chrono::milliseconds init_fetch_timeout,
          std::function<void()> on_transport_established,
          std::function<void()> on_transport_close) {
  const envoy::config::core::v3::ConfigSource config_source = getCiliumXDSAPIConfig(use_delta_xds);
  const envoy::config::core::v3::ApiConfigSource& api_config_source =
      config_source.api_config_source();
  THROW_IF_NOT_OK(Config::Utility::checkApiConfigSourceSubscriptionBackingCluster(
      context.clusterManager().primaryClusters(), api_config_source));

  Config::SubscriptionStats stats = Config::Utility::generateStats(scope);
  Envoy::Config::SubscriptionOptions options;

  // No-op custom validators
  Envoy::Config::CustomConfigValidatorsPtr nop_config_validators =
      std::make_unique<NopConfigValidatorsImpl>();
  auto factory_or_error = Config::Utility::factoryForGrpcApiConfigSource(
      context.clusterManager().grpcAsyncClientManager(), api_config_source, scope, true, 0, false);
  THROW_IF_NOT_OK_REF(factory_or_error.status());

  absl::StatusOr<Config::RateLimitSettings> rate_limit_settings_or_error =
      Config::Utility::parseRateLimitSettings(api_config_source);
  THROW_IF_NOT_OK_REF(rate_limit_settings_or_error.status());

  Config::GrpcMuxContext grpc_mux_context{
      /*async_client_=*/THROW_OR_RETURN_VALUE(
          factory_or_error.value()->createUncachedRawAsyncClient(), Grpc::RawAsyncClientPtr),
      /*failover_async_client_=*/nullptr,
      /*dispatcher_=*/context.mainThreadDispatcher(),
      /*service_method_=*/use_delta_xds ? deltaGrpcMethod(type_url) : sotwGrpcMethod(type_url),
      /*local_info_=*/context.localInfo(),
      /*rate_limit_settings_=*/rate_limit_settings_or_error.value(),
      /*scope_=*/scope,
      /*config_validators_=*/std::move(nop_config_validators),
      /*xds_resources_delegate_=*/absl::nullopt,
      /*xds_config_tracker_=*/absl::nullopt,
      /*backoff_strategy_=*/
      std::make_unique<JitteredExponentialBackOffStrategy>(
          Config::SubscriptionFactory::RetryInitialDelayMs,
          Config::SubscriptionFactory::RetryMaxDelayMs, context.api().randomGenerator()),
      /*target_xds_authority_=*/"",
      /*eds_resources_cache_=*/nullptr // EDS cache is only used for ADS.
  };

  std::shared_ptr<Config::GrpcMux> grpc_mux =
      use_delta_xds ? std::static_pointer_cast<Config::GrpcMux>(std::make_shared<DeltaGrpcMuxImpl>(
                          grpc_mux_context, std::move(on_transport_established),
                          std::move(on_transport_close)))
                    : std::static_pointer_cast<Config::GrpcMux>(std::make_shared<SotwGrpcMuxImpl>(
                          grpc_mux_context, api_config_source.set_node_on_first_message_only(),
                          std::move(on_transport_established), std::move(on_transport_close)));

  return std::make_unique<Config::GrpcSubscriptionImpl>(
      grpc_mux, callbacks, resource_decoder, stats, type_url, context.mainThreadDispatcher(),
      init_fetch_timeout, /*is_aggregated*/ false, options);
}

} // namespace Cilium
} // namespace Envoy
