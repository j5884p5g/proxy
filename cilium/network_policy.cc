#include "cilium/network_policy.h"

#include <fmt/base.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <openssl/mem.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/common/matchers.h"
#include "envoy/common/optref.h"
#include "envoy/config/core/v3/address.pb.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/http/header_map.h"
#include "envoy/init/manager.h"
#include "envoy/network/address.h"
#include "envoy/server/config_tracker.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/type/matcher/v3/metadata.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/common/matchers.h"
#include "source/common/common/thread.h"
#include "source/common/http/header_utility.h"
#include "source/common/init/manager_impl.h"
#include "source/common/init/target_impl.h"
#include "source/common/init/watcher_impl.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"
#include "source/server/transport_socket_config_impl.h"

#include "absl/container/btree_map.h"
#include "absl/container/btree_set.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "cilium/accesslog.h"
#include "cilium/api/npds.pb.h"
#include "cilium/grpc_subscription.h"
#include "cilium/ipcache.h"
#include "cilium/secret_watcher.h"
#include "cilium/versioned.h"

namespace Envoy {
namespace Cilium {

// Supported verdict kinds
using RuleVerdict = enum {
  None = 0,
  Pass = 1,
  Allow = 2,
  Deny = 3,
};

} // namespace Cilium
} // namespace Envoy

namespace fmt {

template <> struct formatter<Envoy::Cilium::RuleVerdict> {
  constexpr auto parse(fmt::format_parse_context& ctx) { return ctx.begin(); }

  template <typename FormatContext>
  auto format(Envoy::Cilium::RuleVerdict verdict, FormatContext& ctx) const {
    absl::string_view name;
    switch (verdict) {
    case Envoy::Cilium::RuleVerdict::None:
      name = "NONE";
      break;
    case Envoy::Cilium::RuleVerdict::Allow:
      name = "ALLOW";
      break;
    case Envoy::Cilium::RuleVerdict::Deny:
      name = "DENY";
      break;
    case Envoy::Cilium::RuleVerdict::Pass:
      name = "PASS";
      break;
    default:
      name = "UNKNOWN";
      break;
    }
    return std::ranges::copy(name, ctx.out()).out;
  }
};

} // namespace fmt

namespace Envoy {
namespace Cilium {

// A specific version of a selector used in a policy. Each update yields a new instance.
class SelectorInstance : public VersionedNode<SelectorInstance>,
                         public absl::flat_hash_set<uint32_t> {};

// Read-only series of specific selector insteances.
class NamedSelectorReadable : public VersionedReadable<SelectorInstance> {
public:
  explicit NamedSelectorReadable(const std::string& name) : name_(name) {}

  const std::string& name() const { return name_; }

private:
  std::string name_;
};

// Stable handle on a read-only selector for accessing specific versions of the selector.
using SelectorHandle = std::shared_ptr<const NamedSelectorReadable>;

// Writable series of selector versions for main-thread updates
class NamedSelectorValue : public VersionedValue<SelectorInstance, NamedSelectorReadable> {
public:
  explicit NamedSelectorValue(const std::string& name)
      : VersionedValue<SelectorInstance, NamedSelectorReadable>(name) {}
};

// Map of named selectors, keyed with xDS resource name
class SelectorMap : public VersionedMap<std::string, SelectorInstance, NamedSelectorValue> {
public:
  using VersionedMap<std::string, SelectorInstance, NamedSelectorValue>::VersionedMap;
};

class PolicyInstanceImpl;

// Stable policy map, usually keyed with endpoint IP (IPv4 and IPv6).
using PolicyMapSnapshot =
    absl::flat_hash_map<std::string, std::shared_ptr<const PolicyInstanceImpl>>;

// variant wrapper for supported resource map keys for delta policy updates
// Delta xDS refers to removed resources by resource name, so we must have a map to
// locate the policy/selector to be removed.
class ResourceKey {
public:
  struct PolicyResourceEntry {
    std::shared_ptr<const PolicyInstanceImpl> policy;
  };

  struct PolicyEndpointIpEntry {};

  struct SelectorResourceEntry {
    SelectorHandle handle;
  };

  static ResourceKey policyResource(const std::shared_ptr<const PolicyInstanceImpl>& policy) {
    return ResourceKey(PolicyResourceEntry{policy});
  }

  static ResourceKey policyEndpointIp() { return ResourceKey(PolicyEndpointIpEntry{}); }

  static ResourceKey selectorResource(const SelectorHandle& handle) {
    return ResourceKey(SelectorResourceEntry{handle});
  }

  const PolicyResourceEntry* policyResourceEntry() const {
    return absl::get_if<PolicyResourceEntry>(&value_);
  }

  const SelectorResourceEntry* selectorResourceEntry() const {
    return absl::get_if<SelectorResourceEntry>(&value_);
  }

  bool isPolicyEndpointIpEntry() const {
    return absl::holds_alternative<PolicyEndpointIpEntry>(value_);
  }

private:
  explicit ResourceKey(const PolicyResourceEntry& value) : value_(value) {}
  explicit ResourceKey(const PolicyEndpointIpEntry& value) : value_(value) {}
  explicit ResourceKey(const SelectorResourceEntry& value) : value_(value) {}

  absl::variant<PolicyResourceEntry, PolicyEndpointIpEntry, SelectorResourceEntry> value_;
};

// Map of Delta xDS resources for name collision and duplicate name detection.
class ResourceMap : public absl::flat_hash_map<std::string, ResourceKey> {
public:
  using absl::flat_hash_map<std::string, ResourceKey>::flat_hash_map;

  const ResourceKey* findEntry(const std::string& key) const {
    auto it = find(key);
    return it != end() ? &it->second : nullptr;
  }

  std::string findPolicyResourceName(const std::shared_ptr<const PolicyInstanceImpl>& policy) const;

  void replaceWith(std::vector<std::pair<std::string, ResourceKey>>&& entries) {
    clear();
    reserve(entries.size());
    for (auto& [key, value] : entries) {
      insert_or_assign(std::move(key), std::move(value));
    }
  }

  void erasePolicyResource(PolicyMapSnapshot& policy_map, const std::string& resource_name,
                           const std::shared_ptr<const PolicyInstanceImpl>& policy);
};

// ResourceMapOverlay lets delta updates stage tentative resource-map removals and insertions on top
// of the current ResourceMap while validation is still in progress. This preserves transactional
// behavior without copying the full map: failed updates can be discarded cheaply, and successful
// ones are applied to the real map only after the whole update has been accepted.
class ResourceMapOverlay {
public:
  ResourceMapOverlay() = default;
  explicit ResourceMapOverlay(const ResourceMap& base) : base_(&base) {}

  const ResourceKey* findEntry(const std::string& key) const {
    auto upsert_it = upserts_.find(key);
    if (upsert_it != upserts_.end()) {
      return &upsert_it->second;
    }
    if (removed_.contains(key)) {
      return nullptr;
    }
    return base_ ? base_->findEntry(key) : nullptr;
  }

  std::string findPolicyResourceName(const std::shared_ptr<const PolicyInstanceImpl>& policy) const;

  std::string describeExistingResourceKey(const std::string& key,
                                          const PolicyMapSnapshot& policy_map) const;

  SelectorHandle getSelectorHandleOrThrow(const std::string& selector) const {
    const auto* entry = findEntry(selector);
    if (entry == nullptr) {
      throw EnvoyException(fmt::format(
          "Delta Network Policy rule references missing selector resource '{}'", selector));
    }
    const auto* selector_entry = entry->selectorResourceEntry();
    if (selector_entry == nullptr || selector_entry->handle == nullptr) {
      throw EnvoyException(
          fmt::format("Delta Network Policy rule references non-selector resource '{}'", selector));
    }
    return selector_entry->handle;
  }

  bool emplace(std::string key, ResourceKey value) {
    if (findEntry(key)) {
      return false;
    }
    removed_.erase(key);
    return upserts_.emplace(std::move(key), std::move(value)).second;
  }

  void insertOrAssign(std::string key, ResourceKey value) {
    removed_.erase(key);
    upserts_.insert_or_assign(std::move(key), std::move(value));
  }

  void erase(const std::string& key) {
    upserts_.erase(key);
    if (base_ && base_->find(key) != base_->end()) {
      removed_.insert(key);
    } else {
      removed_.erase(key);
    }
  }

  bool eraseSelectorResourceIfPresent(const std::string& key) {
    const auto* entry = findEntry(key);
    if (entry == nullptr || entry->selectorResourceEntry() == nullptr) {
      return false;
    }
    erase(key);
    return true;
  }

  bool erasePolicyResourceIfPresent(PolicyMapSnapshot& policy_map,
                                    const std::string& resource_name) {
    const auto* entry = findEntry(resource_name);
    if (entry == nullptr) {
      return false;
    }
    const auto* policy_entry = entry->policyResourceEntry();
    if (policy_entry == nullptr) {
      return false;
    }
    erasePolicyResource(policy_map, resource_name, policy_entry->policy);
    return true;
  }

  void erasePolicyResource(PolicyMapSnapshot& policy_map, const std::string& resource_name,
                           const std::shared_ptr<const PolicyInstanceImpl>& policy);

  void applyTo(ResourceMap& map) && {
    if (!upserts_.empty()) {
      map.reserve(map.size() + upserts_.size());
    }
    for (const auto& key : removed_) {
      map.erase(key);
    }
    for (auto& [key, value] : upserts_) {
      map.insert_or_assign(std::move(key), std::move(value));
    }
  }

private:
  const ResourceMap* base_{};
  absl::flat_hash_set<std::string> removed_;
  absl::flat_hash_map<std::string, ResourceKey> upserts_;
};

// helper for validating resource names.
void validateResourceName(absl::string_view resource_name, absl::string_view subject) {
  if (resource_name.empty()) {
    throw EnvoyException(fmt::format("{} must not be empty", subject));
  }
  if (std::ranges::any_of(resource_name, [](unsigned char c) { return absl::ascii_isspace(c); })) {
    throw EnvoyException(
        fmt::format("{} '{}' must not contain whitespace", subject, resource_name));
  }
}

// PolicyStreamState is shared by all policies created from one accepted NPDS stream generation.
// Same-stream selector-only updates publish a newer selector version into this object so existing
// policies follow immediately. When the NPDS stream restarts, new policies get a fresh state
// object while old policies keep the old one until the old policy map has quiesced and been
// retired. This allows the new stream to reuse selector resource names so that the xDS server
// need not keep selector resource names in stable storage accross restarts.
class PolicyStreamState {
public:
  explicit PolicyStreamState(uint64_t stream_generation, SelectorVersion version = versionMin)
      : stream_generation_(stream_generation), version_(version) {}

  uint64_t streamGeneration() const { return stream_generation_; }

  SelectorVersion version() const { return version_.load(std::memory_order_acquire); }

  void publishVersion(SelectorVersion version) {
    version_.store(version, std::memory_order_release);
  }

private:
  const uint64_t stream_generation_;
  std::atomic<SelectorVersion> version_;
};
using PolicyStreamStateSharedPtr = std::shared_ptr<PolicyStreamState>;
using PolicyStreamStateConstSharedPtr = std::shared_ptr<const PolicyStreamState>;

namespace {
constexpr absl::string_view WildcardResourceName = "*";
} // namespace

class NetworkPolicyMapImpl : public Envoy::Config::SubscriptionCallbacks,
                             public Logger::Loggable<Logger::Id::config>,
                             public std::enable_shared_from_this<NetworkPolicyMapImpl> {
public:
  friend class PortNetworkPolicyRule;
  NetworkPolicyMapImpl(Server::Configuration::FactoryContext& context, bool use_delta_xds);
  ~NetworkPolicyMapImpl() override;

  void subscribe();

  // This is used for testing with a file-based subscription
  void subscribe(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    subscription_ = std::move(subscription);
    subscription_use_delta_xds_ = desired_use_delta_xds_;
    subscription_connected_ = false;
  }

  // Config::SubscriptionCallbacks
  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& resources,
                              const std::string& version_info) override;
  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
                              const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                              const std::string& system_version_info) override;
  void onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason,
                            const EnvoyException* e) override;

  Server::Configuration::TransportSocketFactoryContext& transportFactoryContext() const {
    return *transport_factory_context_;
  }

  Regex::Engine& regexEngine() const { return context_.regexEngine(); }

  void tlsWrapperMissingPolicyInc() const { stats_.tls_wrapper_missing_policy_.inc(); }

  bool useDeltaXds() const { return desired_use_delta_xds_; }

  void setUseDeltaXds(bool use_delta_xds) {
    desired_use_delta_xds_ = use_delta_xds;
    if (!subscription_connected_ && subscription_ != nullptr) {
      subscription_connected_ = grpcStreamConnected(subscription_.get());
    }
    maybeRecreateSubscriptionInDesiredMode();
  }

protected:
  uint64_t streamGeneration() const { return subscription_stream_generation_; }
  void resetStreamForTest() { subscription_stream_generation_++; }

  // run the given function after all the threads have scheduled
  void runAfterAllThreads(std::function<void()> cb) const {
    // We can guarantee the callback 'cb' runs in the main thread after all worker threads have
    // entered their event loop, and thus relinquished all state, such as policy lookup results that
    // were stored in their call stack, by posting and empty function to their event queues and
    // waiting until all of them have returned, as managed by 'runOnAllWorkerThreads'.
    context_.threadLocal().runOnAllWorkerThreads([]() {}, cb);
  }

  void reopenIpcache();

  std::shared_ptr<const PolicyInstanceImpl>
  createOrReusePolicy(const std::string& resource_name, const cilium::NetworkPolicy& config,
                      const PolicyStreamStateConstSharedPtr& policy_stream_state,
                      const ResourceMap& resource_map,
                      const ResourceMapOverlay* pending_resource_map);

  SelectorHandle createOrReuseSelector(const std::string& resource_name,
                                       const cilium::Selector& config, uint64_t update_version);

  void installNewPolicyMap(PolicyMapSnapshot&& new_policy_map,
                           Init::ManagerImpl& version_init_manager, std::string&& version_name,
                           const PolicyStreamStateSharedPtr& policy_stream_state);

private:
  void startSubscription() {
    ASSERT(subscription_ != nullptr);
    if (subscription_use_delta_xds_) {
      // NPDS always wants all resources, so use an explicit wildcard subscription in delta xDS.
      subscription_->start({std::string(WildcardResourceName)});
    } else {
      subscription_->start({});
    }
  }

  void onSubscriptionTransportEstablished(uint64_t subscription_id) {
    ++subscription_stream_generation_;

    if (subscription_id != subscription_id_) {
      return;
    }
    subscription_connected_ = true;
  }

  void onSubscriptionTransportClosed(uint64_t subscription_id) {
    if (subscription_id != subscription_id_) {
      return;
    }
    subscription_connected_ = false;
    maybeRecreateSubscriptionInDesiredMode();
  }

  void maybeRecreateSubscriptionInDesiredMode() {
    if (subscription_ == nullptr || subscription_connected_ ||
        desired_use_delta_xds_ == subscription_use_delta_xds_) {
      return;
    }
    subscribe();
  }

  // Helpers for atomic swap of the policy map pointer.
  //
  // store() is only used for the initialization of the map during construction.
  // exchange() is used to atomically swap in a new map, the old map pointer is returned.
  // Once a map is stored or swapped in to the atomic pointer by the main thread, it may be "loaded"
  // from the atomic pointer by any thread. This is why the load returns a const pointer.
  //
  // For the loaded pointer to be safe to use, we must use acquire/release memory ordering:
  // - when a pointer stored or swapped in, 'std::memory_order_release' informs the compiler to make
  //   sure it is not reordering any write operations into the map to happen after the pointer is
  //   written, and emits CPU instructions to also make the CPU out-of-order-execution logic to not
  //   reorder any write operations to happen after the pointer itself is written. This guarantees
  //   that the map is not modified after the point when the worker threads can observe the new
  //   pointer value, i.e., the map is actaully immutable (const) from that point forward.
  // - when the pointer is read (by a worker thread) 'std::memory_order_acquire' in the load
  //   operation informs the compiler to emit CPU instructions to make the CPU
  //   out-of-order-execution logic to not reorder any reads from the new map to happen before the
  //   pointer itself is read, so that no values from the map are read before the map was "released"
  //   by the store or exchange operation.
  //
  // Typically it is easier to think about the release part of the acquire/release semantics, as at
  // the point of the store or exchange operation the compiler and the CPU know the location of the
  // map in memory before and after the pointer is stored, so that without
  // 'std::memory_order_release' there is an understandable risk of such write after release
  // happening. On the acquire side it seems less likely that the compiler or the CPU could know the
  // new map pointer value in advance and even try to reorder any read operations to happen before
  // the pointer is actually read. But consider the typical case where the pointer value is actually
  // not changing between consecutice load operations. The compiler or the CPU could speculate that
  // to be the case and read some values from the old memory location. 'std::memory_order_acquire'
  // tells the compiler (which then "tells" the CPU) that this can not be done, and all reads must
  // actually happen after the pointer value is loaded, be it a new one or the same as before.
  //
  const PolicyMapSnapshot* load() const { return map_ptr_.load(std::memory_order_acquire); }
  void store(const PolicyMapSnapshot* map) { map_ptr_.store(map, std::memory_order_release); }
  const PolicyMapSnapshot* exchange(const PolicyMapSnapshot* map) {
    return map_ptr_.exchange(map, std::memory_order_release);
  }

  const PolicyInstance* getPolicyInstanceImpl(const std::string& endpoint_policy_name) const;
  PolicyInstanceConstSharedPtr
  getPolicyInstanceSharedImpl(const std::string& endpoint_policy_name) const;
  uint64_t policySelectorStreamGenerationForTestImpl(const PolicyInstance& policy) const;
  SelectorVersion policySelectorVersionForTestImpl(const PolicyInstance& policy) const;
  void removeInitManager();
  void scheduleSelectorDeferredDeletion(DeferredDeletion<SelectorInstance>&& deferred);
  void scheduleSelectorGCAndDeferredDeletion(uint64_t published_version,
                                             const PolicyMapSnapshot* old_policy_map = nullptr);
  void startManagedSubscriptionForTest() {
    subscription_should_start_ = true;
    subscribe();
  }
  void setSubscriptionFactoryForTest(NetworkPolicyMap::SubscriptionFactoryForTest factory) {
    subscription_factory_for_test_ = std::move(factory);
  }
  void onSubscriptionConnectedForTest() { onSubscriptionTransportEstablished(subscription_id_); }
  void onSubscriptionTransportCloseForTest() { onSubscriptionTransportClosed(subscription_id_); }
  bool subscriptionUseDeltaXdsForTest() const { return subscription_use_delta_xds_; }
  bool subscriptionConnectedForTest() const { return subscription_connected_; }

  static uint64_t instance_id_;

  bool desired_use_delta_xds_;
  bool subscription_use_delta_xds_;
  bool subscription_connected_{false};
  bool subscription_should_start_{false};
  uint64_t subscription_id_{0};
  Server::Configuration::ServerFactoryContext& context_;

  std::atomic<const PolicyMapSnapshot*> map_ptr_;
  SelectorMap selector_map_;
  // Policies hold a shared per-stream state object. A freshly installed stream stores its actual
  // gRPC stream generation here, so same-stream selector-only updates advance existing policies
  // immediately while old policies remain pinned to the latest selector version reached by their
  // own stream.
  PolicyStreamStateSharedPtr policy_stream_state_{std::make_shared<PolicyStreamState>(0)};
  ResourceMap resource_map_;
  Stats::ScopeSharedPtr npds_stats_scope_;
  Stats::ScopeSharedPtr policy_stats_scope_;

  // init target which starts gRPC subscription
  Init::TargetImpl init_target_;
  std::shared_ptr<Server::Configuration::TransportSocketFactoryContextImpl>
      transport_factory_context_;

  std::unique_ptr<Envoy::Config::Subscription> subscription_;
  static uint64_t subscription_stream_generation_;
  NetworkPolicyMap::SubscriptionFactoryForTest subscription_factory_for_test_;

  ProtobufTypes::MessagePtr dumpNetworkPolicyConfigs(const Matchers::StringMatcher& name_matcher);
  Server::ConfigTracker::EntryOwnerPtr config_tracker_entry_;

protected:
  friend class NetworkPolicyMap;

  PolicyStats stats_;
};

uint64_t NetworkPolicyMapImpl::instance_id_ = 0;
uint64_t NetworkPolicyMapImpl::subscription_stream_generation_ = 1;

IpAddressPair::IpAddressPair(const cilium::NetworkPolicy& proto) {
  for (const auto& ip_addr : proto.endpoint_ips()) {
    auto ip = Network::Utility::parseInternetAddressNoThrow(ip_addr);
    if (ip) {
      switch (ip->ip()->version()) {
      case Network::Address::IpVersion::v4:
        ipv4_ = std::move(ip);
        break;
      case Network::Address::IpVersion::v6:
        ipv6_ = std::move(ip);
        break;
      }
    }
  }
}

class HeaderMatch : public Logger::Loggable<Logger::Id::config> {
public:
  HeaderMatch(const NetworkPolicyMapImpl& parent, const cilium::HeaderMatch& config)
      : name_(config.name()), value_(config.value()), match_action_(config.match_action()),
        mismatch_action_(config.mismatch_action()) {
    if (!config.value_sds_secret().empty()) {
      secret_ = std::make_unique<SecretWatcher>(parent.transportFactoryContext(),
                                                config.value_sds_secret());
    }
  }

  void logRejected(Cilium::AccessLog::Entry& log_entry, absl::string_view value) const {
    log_entry.addRejected(name_.get(), !secret_ ? value : "[redacted]");
  }

  void logMissing(Cilium::AccessLog::Entry& log_entry, absl::string_view value) const {
    log_entry.addMissing(name_.get(), !secret_ ? value : "[redacted]");
  }

  // Returns 'true' if matching can continue
  bool allowed(Envoy::Http::RequestHeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
    bool matches = false;
    const std::string* match_value = &value_;
    const auto header_value = Http::HeaderUtility::getAllOfHeaderAsString(headers, name_);

    // Get secret value?
    if (secret_) {
      auto* secret_value = secret_->value();
      if (secret_value) {
        match_value = secret_value;
      } else if (value_.empty()) {
        // fail if secret has no value and the inline value to match is also empty
        ENVOY_LOG(info, "Cilium HeaderMatch missing SDS secret value for header {}", name_);
        return false;
      }
    }

    // Perform presence match if the value to match is empty
    bool is_present_match = match_value->empty();
    if (is_present_match) {
      matches = header_value.result().has_value();
    } else if (header_value.result().has_value()) {
      const absl::string_view val = header_value.result().value();
      if (val.length() == match_value->length()) {
        // Use constant time comparison for security reason
        matches = CRYPTO_memcmp(val.data(), match_value->data(), match_value->length()) == 0;
      }
    }

    if (matches) {
      // Match action
      switch (match_action_) {
      case cilium::HeaderMatch::CONTINUE_ON_MATCH:
        return true;
      case cilium::HeaderMatch::FAIL_ON_MATCH:
      default: // fail closed if unknown action
        logRejected(log_entry, *match_value);
        return false;
      case cilium::HeaderMatch::DELETE_ON_MATCH:
        logRejected(log_entry, *match_value);
        headers.remove(name_);
        return true;
      }
    } else {
      // Mismatch action
      switch (mismatch_action_) {
      case cilium::HeaderMatch::FAIL_ON_MISMATCH:
      default:
        logMissing(log_entry, *match_value);
        return false;
      case cilium::HeaderMatch::CONTINUE_ON_MISMATCH:
        logMissing(log_entry, *match_value);
        return true;
      case cilium::HeaderMatch::ADD_ON_MISMATCH:
        headers.addCopy(name_, *match_value);
        logMissing(log_entry, *match_value);
        return true;
      case cilium::HeaderMatch::DELETE_ON_MISMATCH:
        if (is_present_match) {
          // presence match failed, nothing to do
          return true;
        }
        if (!header_value.result().has_value()) {
          return true; // nothing to remove
        }

        // Remove the header with an incorrect value
        headers.remove(name_);
        logRejected(log_entry, header_value.result().value());
        return true;
      case cilium::HeaderMatch::REPLACE_ON_MISMATCH:
        // Log the wrong value as rejected, if the header existed with a wrong value
        if (header_value.result().has_value()) {
          logRejected(log_entry, header_value.result().value());
        }
        // Set the expected value
        headers.setCopy(name_, *match_value);
        // Log the expected value as missing
        logMissing(log_entry, *match_value);
        return true;
      }
    }
    IS_ENVOY_BUG("HeaderMatch reached unreachable return");
    return false;
  }

  void toString(int indent, std::string& res) const {
    res.append(indent - 2, ' ').append("- name: \"").append(name_.get()).append("\"\n");
    if (!value_.empty()) {
      res.append(indent, ' ').append("value: \"").append(value_).append("\"\n");
    }
    if (secret_) {
      res.append(indent, ' ').append("secret: \"").append(secret_->name()).append("\"\n");
    }
    const char* match_actions[] = {"CONTINUE", "FAIL", "DELETE", "UNKNOWN"};
    res.append(indent, ' ')
        .append("match_action: ")
        .append(match_actions[std::max(int(match_action_), 3)])
        .append("\n");

    const char* mismatch_actions[] = {"FAIL", "CONTINUE", "ADD", "DELETE", "REPLACE", "UNKNOWN"};
    res.append(indent, ' ')
        .append("mismatch_action: ")
        .append(mismatch_actions[std::max(int(mismatch_action_), 5)])
        .append("\n");
  }

  const Http::LowerCaseString name_;
  std::string value_;
  cilium::HeaderMatch::MatchAction match_action_;
  cilium::HeaderMatch::MismatchAction mismatch_action_;
  SecretWatcherPtr secret_;
};

class HttpNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
  HttpNetworkPolicyRule(const NetworkPolicyMapImpl& parent,
                        const cilium::HttpNetworkPolicyRule& rule) {
    ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule():");
    headers_.reserve(rule.headers().size());
    for (const auto& header : rule.headers()) {
      headers_.emplace_back(Http::HeaderUtility::createHeaderData(
          header, parent.transportFactoryContext().serverFactoryContext()));

      auto value = header.has_range_match()   ? fmt::format("[{}-{})", header.range_match().start(),
                                                            header.range_match().end())
                   : header.has_exact_match() ? "<VALUE>"
                   : header.has_present_match()    ? "<PRESENT>"
                   : header.has_safe_regex_match() ? "<REGEX>"
                                                   : "<UNKNOWN>";
      ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule(): HeaderData {}={}", header.name(), value);
    }
    header_matches_.reserve(rule.header_matches().size());
    for (const auto& config : rule.header_matches()) {
      header_matches_.emplace_back(parent, config);
      const auto& header_match = header_matches_.back();
      ENVOY_LOG(trace,
                "Cilium L7 HttpNetworkPolicyRule(): HeaderMatch {}={} (match: {}, mismatch: {})",
                header_match.name_.get(),
                header_match.secret_ ? fmt::format("<SECRET {}>", header_match.secret_->name())
                : !header_match.value_.empty() ? header_match.value_
                                               : "<PRESENT>",
                cilium::HeaderMatch::MatchAction_Name(header_match.match_action_),
                cilium::HeaderMatch::MismatchAction_Name(header_match.mismatch_action_));
    }
  }

  bool allowed(const Envoy::Http::RequestHeaderMap& headers) const {
    // Empty set matches any headers.
    return Http::HeaderUtility::matchHeaders(headers, headers_);
  }

  // Should only be called after 'allowed' returns 'true'.
  // Returns 'true' if matching can continue
  bool headerMatches(Envoy::Http::RequestHeaderMap& headers,
                     Cilium::AccessLog::Entry& log_entry) const {
    bool accepted = true;
    for (const auto& header_match : header_matches_) {
      if (!header_match.allowed(headers, log_entry)) {
        accepted = false;
      }
    }
    return accepted;
  }

  void toString(int indent, std::string& res) const {
    bool first = true;
    if (!headers_.empty()) {
      if (first) {
        first = false;
        res.append(indent - 2, ' ').append("- ");
      } else {
        res.append(indent, ' ');
      }
      res.append("headers:\n");
      for (auto& h : headers_) {
        if (const auto v = dynamic_cast<Http::HeaderUtility::HeaderDataBaseImpl*>(h.get())) {
          res.append(indent, ' ').append("- name: \"").append(v->name_).append("\"\n");
        }

        if (const auto v = dynamic_cast<Http::HeaderUtility::HeaderDataExactMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("value: \"").append(v->expected_value_).append("\"\n");
        } else if (dynamic_cast<Http::HeaderUtility::HeaderDataRegexMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("regex: ").append("<hidden>\n");
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataRangeMatch*>(h.get())) {
          res.append(indent + 2, ' ')
              .append("range: ")
              .append(fmt::format("[{}-{})\n", v->range_start_, v->range_end_));
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataPresentMatch*>(h.get())) {
          res.append(indent + 2, ' ')
              .append("present: ")
              .append(v->present_ ? "true\n" : "false\n");
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataPrefixMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("prefix: \"").append(v->prefix_).append("\"\n");
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataSuffixMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("suffix: \"").append(v->suffix_).append("\"\n");
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataContainsMatch*>(h.get())) {
          res.append(indent + 2, ' ')
              .append("contains: \"")
              .append(v->expected_substr_)
              .append("\"\n");
        } else if (dynamic_cast<Http::HeaderUtility::HeaderDataStringMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("string_match: ").append("<hidden>\n");
        }

        if (const auto v = dynamic_cast<Http::HeaderUtility::HeaderDataBaseImpl*>(h.get())) {
          if (v->invert_match_) {
            res.append(indent + 2, ' ').append("invert_match: true\n");
          }

          if (v->treat_missing_as_empty_) {
            res.append(indent + 2, ' ').append("treat_missing_as_empty: true\n");
          }
        }
      }
    }
    if (!header_matches_.empty()) {
      if (first) {
        // first = false; // not used after, so no need to update
        res.append(indent - 2, ' ').append("- ");
      } else {
        res.append(indent, ' ');
      }
      res.append("header_matches:\n");
      for (auto& hm : header_matches_) {
        hm.toString(indent + 2, res);
      }
    }
  }

  std::vector<Http::HeaderUtility::HeaderDataPtr> headers_; // Allowed if empty.
  std::vector<HeaderMatch> header_matches_;
};

class L7NetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
  L7NetworkPolicyRule(const NetworkPolicyMapImpl& parent, const cilium::L7NetworkPolicyRule& rule)
      : name_(rule.name()) {
    for (const auto& matcher : rule.metadata_rule()) {
      metadata_matchers_.emplace_back(matcher,
                                      parent.transportFactoryContext().serverFactoryContext());
      matchers_.emplace_back(matcher);
    }
  }

  bool matches(const envoy::config::core::v3::Metadata& metadata) const {
    // All matchers must be satisfied for the rule to match
    for (const auto& metadata_matcher : metadata_matchers_) {
      if (!metadata_matcher.match(metadata)) {
        return false;
      }
    }
    return true;
  }

  void toString(int indent, std::string& res) const {
    res.append(indent - 2, ' ').append("- name: \"").append(name_).append("\"\n");
  }

  std::string name_;

private:
  std::vector<Envoy::Matchers::MetadataMatcher> metadata_matchers_;
  std::vector<envoy::type::matcher::v3::MetadataMatcher> matchers_;
};

// Constructs SniPattern with the provided regex engine for input match pattern.
SniPattern::SniPattern(const Regex::Engine& engine, absl::string_view sni) {
  if (!isValid(sni)) {
    throw EnvoyException(fmt::format("SniPattern: Unsupported match pattern {}", sni));
  }

  // Only regex characters supported in valid match pattern is '*'. If not present, pattern
  // can be reduced to explicit full match.
  if (!absl::StrContains(sni, '*')) {
    match_name_ = absl::AsciiStrToLower(sni);
    return;
  }

  std::string regex_expr;
  if (sni == "*") {
    // For a full wildcard match pattern replace with static wildcard pattern for DNS characters.
    regex_expr = "[-a-z0-9_]+([.][-a-z0-9_]+)*";
  } else {
    // NOTE: We already validated that the provided pattern cannot have more than 2 consecutive
    // wildcard specifier('*'). This simplifies the regex replacement by isolating '**' and '*'
    // specifiers.
    regex_expr = absl::StrReplaceAll(
        absl::AsciiStrToLower(sni),
        {
            // Convert '.' to regex literal '[.]'
            {".", "[.]"},

            // '**' expands to regex for multilevel subdomain match.
            // The replaced regex pattern matches one or more entire DNS labels, for example:
            // * <dns-label>
            // * <dns-label-1>.<dns-label-2>.<dns-label-3>
            {"**", "[-a-z0-9_]+([.][-a-z0-9_]+){0,}"},

            // Replace wildcard specifier '*' with regex for any number of valid DNS characters
            // within subdomain boundry(doesn't include '.' literal).
            {"*", "[-a-z0-9_]{0,}"},
        });
  }

  auto regex_matcher = engine.matcher(regex_expr);
  if (!regex_matcher.ok()) {
    throw EnvoyException(fmt::format("SniPattern: Failed to create pattern for SNI {} - {}", sni,
                                     regex_matcher.status().ToString()));
  }

  matcher_ = std::move(regex_matcher.value());
}

class PortNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicyRule()
      : name_("default allow rule"), verdict_(RuleVerdict::Allow), proxy_id_(0), precedence_(0),
        tier_last_precedence_(0), pass_index_(0), l7_proto_("") {}

  PortNetworkPolicyRule(const NetworkPolicyMapImpl& parent,
                        const cilium::PortNetworkPolicyRule& rule,
                        const ResourceMapOverlay* resource_map)
      : name_(rule.name()),
        verdict_(rule.pass_precedence() ? RuleVerdict::Pass
                                        : (rule.deny() ? RuleVerdict::Deny : RuleVerdict::Allow)),
        proxy_id_(uint16_t(rule.proxy_id())), precedence_(rule.precedence()),
        tier_last_precedence_(rule.pass_precedence()), pass_index_(0), l7_proto_(rule.l7_proto()) {
    if (tier_last_precedence_ > precedence_) {
      throw EnvoyException(
          fmt::format("PortNetworkPolicyRule: pass_precedence {} must be lower than precedence {}",
                      tier_last_precedence_, precedence_));
    }
    if (resource_map) {
      if (rule.remote_policies_size()) {
        throw EnvoyException(
            "Delta Network Policy rule must use selectors instead of remote_policies");
      }
      selectors_.reserve(rule.selectors_size());
      for (const auto& selector : rule.selectors()) {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): {} selector {} by rule: {}", verdict_,
                  selector, name_);
        selectors_.emplace_back(resource_map->getSelectorHandleOrThrow(selector));
      }
    } else {
      if (rule.selectors_size()) {
        throw EnvoyException("State-of-the-world Network Policy rule must not use selectors");
      }
      for (const auto remote : rule.remote_policies()) {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): {} remote {} by rule: {}", verdict_,
                  remote, name_);
        remotes_.emplace(remote);
      }
    }
    if (rule.has_downstream_tls_context()) {
      auto config = rule.downstream_tls_context();
      server_context_ =
          std::make_unique<DownstreamTLSContext>(parent.transportFactoryContext(), config);
    }
    if (rule.has_upstream_tls_context()) {
      auto config = rule.upstream_tls_context();
      client_context_ =
          std::make_unique<UpstreamTLSContext>(parent.transportFactoryContext(), config);
    }
    for (const auto& sni : rule.server_names()) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): {} SNI {} by rule {}", verdict_, sni,
                name_);
      allowed_snis_.emplace_back(parent.regexEngine(), sni);
    }
    if (rule.has_http_rules()) {
      http_rules_ = std::make_shared<std::vector<HttpNetworkPolicyRule>>();
      for (const auto& http_rule : rule.http_rules().http_rules()) {
        if (http_rule.header_matches_size() > 0) {
          has_headermatches_ = true;
        }
        http_rules_->emplace_back(parent, http_rule);
      }
    }
    if (!l7_proto_.empty() && rule.has_l7_rules()) {
      const auto& ruleset = rule.l7_rules();
      for (const auto& l7_rule : ruleset.l7_deny_rules()) {
        l7_deny_rules_.emplace_back(parent, l7_rule);
      }
      for (const auto& l7_rule : ruleset.l7_allow_rules()) {
        l7_allow_rules_.emplace_back(parent, l7_rule);
      }
    }
  }

  bool isRemoteWildcard() const { return remotes_.empty() && selectors_.empty(); }

  bool matchesRemoteId(uint32_t remote_id, const SelectorVersion selector_version) const {
    if (isRemoteWildcard()) {
      return true;
    }
    if (!remotes_.empty()) {
      return remotes_.contains(remote_id);
    }

    for (const auto& selector : selectors_) {
      const auto resolved_selector = selector->get(selector_version);
      if (resolved_selector && resolved_selector->contains(remote_id)) {
        return true;
      }
    }
    return false;
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id,
                         const SelectorVersion selector_version) const {
    // proxy_id must match if we have any.
    if (proxy_id_ && proxy_id != proxy_id_) {
      return RuleVerdict::None;
    }
    // Remote ID must match if we have any.
    if (!matchesRemoteId(remote_id, selector_version)) {
      return RuleVerdict::None; // no verdict
    }
    ASSERT(verdict_ != RuleVerdict::None, "rule must have a verdict");
    return verdict_;
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
                         const SelectorVersion selector_version) const {
    // sni must match if we have any
    if (!allowed_snis_.empty() &&
        (sni.empty() || std::ranges::none_of(allowed_snis_, [&](const auto& pattern) {
           return pattern.matches(sni);
         }))) {
      return RuleVerdict::None;
    }
    return getVerdict(proxy_id, remote_id, selector_version);
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id,
                         Envoy::Http::RequestHeaderMap& headers,
                         Cilium::AccessLog::Entry& log_entry,
                         const SelectorVersion selector_version) const {
    auto verdict = getVerdict(proxy_id, remote_id, selector_version);
    if (!hasHttpRules() || verdict != RuleVerdict::Allow) {
      return verdict;
    }
    if (!has_headermatches_) {
      if (std::ranges::any_of(*http_rules_, [&](auto& r) { return r.allowed(headers); })) {
        return RuleVerdict::Allow;
      }
      return RuleVerdict::None;
    }

    // Evaluate all rules to run all the header actions,
    // and remember if any of them matched
    bool header_matched = false;
    for (const auto& rule : *http_rules_) {
      if (rule.allowed(headers)) {
        if (rule.headerMatches(headers, log_entry)) {
          header_matched = true;
        }
      }
    }
    return (header_matched) ? RuleVerdict::Allow : RuleVerdict::None;
  }

  RuleVerdict useProxylib(uint16_t proxy_id, uint32_t remote_id, std::string& l7_proto,
                          const SelectorVersion selector_version) const {
    auto verdict = getVerdict(proxy_id, remote_id, selector_version);
    if (verdict != RuleVerdict::Allow) {
      return verdict;
    }
    if (!l7_proto_.empty()) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule::useProxylib(): returning {}", l7_proto_);
      l7_proto = l7_proto_;
      return RuleVerdict::Allow; // found a proxylib match
    }
    // keep looking past allows if no proxylib
    return RuleVerdict::None;
  }

  // Envoy Metadata matcher, called after deny has already been checked for
  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id,
                         const envoy::config::core::v3::Metadata& metadata,
                         const SelectorVersion selector_version) const {
    auto verdict = getVerdict(proxy_id, remote_id, selector_version);
    if (verdict != RuleVerdict::Allow) {
      return verdict;
    }

    if (std::ranges::any_of(l7_deny_rules_,
                            [&](const auto& rule) { return rule.matches(metadata); })) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule: DENY due to a matching deny rule");
      return RuleVerdict::Deny; // request is denied if any deny rule matches
    }

    if (l7_allow_rules_.empty()) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule: default ALLOW due to no allow rules");
      return RuleVerdict::Allow; // allowed by default
    }

    if (std::ranges::any_of(l7_allow_rules_,
                            [&](const auto& rule) { return rule.matches(metadata); })) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule: ALLOW due to a matching allow rule");
      return RuleVerdict::Allow;
    }

    ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule: SKIP due to all allow rules mismatching");
    return RuleVerdict::None;
  }

  // getServerTlsContext returns true if the rule has server TLS context that was passed to the
  // caller via the reference arguments.
  bool getServerTlsContext(Ssl::ContextSharedPtr& tls_context,
                           const Ssl::ContextConfig*& config) const {
    if (server_context_) {
      tls_context = server_context_->getTlsContext();
      config = &server_context_->getTlsContextConfig();
      return true;
    }
    return false;
  }

  // getClientTlsContext returns true if the rule has client TLS context that was passed to the
  // caller via the reference arguments.
  bool getClientTlsContext(Ssl::ContextSharedPtr& tls_context,
                           const Ssl::ContextConfig*& config) const {
    if (client_context_) {
      tls_context = client_context_->getTlsContext();
      config = &client_context_->getTlsContextConfig();
      return true;
    }
    return false;
  }

  void toString(int indent, std::string& res) const {
    if (!selectors_.empty()) {
      res.append(indent - 2, ' ').append("- selectors: [");
      std::vector<std::string> quoted_selectors;
      quoted_selectors.reserve(selectors_.size());
      for (const auto& selector : selectors_) {
        quoted_selectors.emplace_back(fmt::format("\"{}\"", selector->name()));
      }
      res.append(fmt::format("{}", fmt::join(quoted_selectors, ",")));
    } else {
      res.append(indent - 2, ' ').append("- remotes: [");
      res.append(fmt::format("{}", fmt::join(remotes_, ",")));
    }
    res.append("]\n");

    if (!name_.empty()) {
      res.append(indent, ' ').append("name: \"").append(name_).append("\"\n");
    }
    if (verdict_ == RuleVerdict::Deny) {
      res.append(indent, ' ').append("deny: true\n");
    }
    if (precedence_) {
      res.append(indent, ' ').append(fmt::format("precedence: {}\n", precedence_));
    }
    if (tier_last_precedence_) {
      res.append(indent, ' ')
          .append(fmt::format("tier_last_precedence: {}\n", tier_last_precedence_));
    }
    if (proxy_id_) {
      res.append(indent, ' ').append(fmt::format("proxy_id: {}\n", proxy_id_));
    }

    if (!allowed_snis_.empty()) {
      res.append(indent, ' ').append("allowed_snis: [");
      int count = 0;
      for (auto& sni : allowed_snis_) {
        if (count++ > 0) {
          res.append(",");
        }
        sni.toString(res);
      }
      res.append("]\n");
    }

    if (hasHttpRules()) {
      res.append(indent, ' ').append("http_rules:\n");
      for (auto& rule : *http_rules_) {
        rule.toString(indent + 2, res);
      }
    }

    if (!l7_proto_.empty()) {
      res.append(indent, ' ').append("l7_proto: \"").append(l7_proto_).append("\"\n");
    }
    if (!l7_allow_rules_.empty()) {
      res.append(indent, ' ').append("l7_allow_rules:\n");
      for (auto& rule : l7_allow_rules_) {
        rule.toString(indent + 2, res);
      }
    }
    if (!l7_deny_rules_.empty()) {
      res.append(indent, ' ').append("l7_deny_rules:\n");
      for (auto& rule : l7_deny_rules_) {
        rule.toString(indent + 2, res);
      }
    }
  }

  bool hasHttpRules() const { return http_rules_ && !http_rules_->empty(); }

  std::string name_;
  DownstreamTLSContextSharedPtr server_context_;
  UpstreamTLSContextSharedPtr client_context_;
  bool has_headermatches_{false};
  const RuleVerdict verdict_;
  const uint16_t proxy_id_;
  uint32_t precedence_;
  const uint32_t tier_last_precedence_;
  uint32_t pass_index_;
  absl::btree_set<uint32_t> remotes_;
  std::vector<SelectorHandle> selectors_;

  std::vector<SniPattern> allowed_snis_; // All SNIs allowed if empty.
  std::shared_ptr<std::vector<HttpNetworkPolicyRule>>
      http_rules_; // Allowed if empty, but remote is checked first.
  std::string l7_proto_;
  std::vector<L7NetworkPolicyRule> l7_allow_rules_;
  std::vector<L7NetworkPolicyRule> l7_deny_rules_;
};
using PortNetworkPolicyRuleSharedPtr = std::shared_ptr<PortNetworkPolicyRule>;
using PortNetworkPolicyRuleConstSharedPtr = std::shared_ptr<const PortNetworkPolicyRule>;

class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicyRules() = default;

  ~PortNetworkPolicyRules() {
    if (!Thread::MainThread::isMainOrTestThread()) {
      IS_ENVOY_BUG("PortNetworkPolicyRules: Destructor executing in a worker thread, while "
                   "only main thread should destruct xDS resources");
    }
  }

  void clear() {
    rules_.clear();
    can_short_circuit_ = true;
    has_pass_rules_ = false;
  }

  // Move assignment operator
  PortNetworkPolicyRules& operator=(PortNetworkPolicyRules&& other) noexcept = default;

  // Move constructor
  PortNetworkPolicyRules(PortNetworkPolicyRules&& other) noexcept = default;

  // Copy constructors
  PortNetworkPolicyRules& operator=(const PortNetworkPolicyRules&) = default;
  PortNetworkPolicyRules(const PortNetworkPolicyRules&) = default;

  void updateFor(const PortNetworkPolicyRuleConstSharedPtr& rule) {
    if (rule->has_headermatches_) {
      can_short_circuit_ = false;
    }
    if (rule->tier_last_precedence_) {
      has_pass_rules_ = true;
    }
  }

  void addDefaultAllowRule() { rules_.emplace_back(std::make_shared<PortNetworkPolicyRule>()); }

  // append merges 'rules' to 'rules_' by placing the new 'rules' to the end of 'rules_'.
  // First call marks 'rules_' as initialized. Of further calls, if either is empty,
  // we must add a default allow rule to retain the semantics of empty rules.
  void append(const NetworkPolicyMapImpl& parent,
              const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules,
              const ResourceMapOverlay* selector_resource_map) {
    if (initialized_ && rules.empty() != rules_.empty()) {
      // add an explicit allow-all rule to keep the combined semantics
      addDefaultAllowRule();
    }
    for (const auto& it : rules) {
      rules_.emplace_back(
          std::make_shared<PortNetworkPolicyRule>(parent, it, selector_resource_map));
      updateFor(rules_.back());
    }
    initialized_ = true;
  }

  // prepend merges 'rules' to 'rules_' by placing the new 'rules' to the front of 'rules_'.
  // First call marks 'rules_' as initialized. Of further calls, if either is empty,
  // we must add a default allow rule to retain the semantics of an empty rules.
  void prepend(const NetworkPolicyMapImpl& parent,
               const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules,
               const ResourceMapOverlay* resource_map) {
    if (initialized_ && rules.empty() != rules_.empty()) {
      // add an explicit allow-all rule to keep the combined semantics
      rules_.emplace(rules_.begin(), std::make_shared<PortNetworkPolicyRule>());
    }
    for (const auto& it : rules) {
      rules_.emplace(rules_.begin(),
                     std::make_shared<PortNetworkPolicyRule>(parent, it, resource_map));
      updateFor(rules_.front());
    }
    initialized_ = true;
  }

  // appendRules merges all rules from 'rules' to the end of 'rules_'.
  // First call marks 'rules_' as initialized. Of further calls, if either is empty,
  // we must add a default allow rule to retain the semantics of the combined rules.
  void appendRules(const std::vector<PortNetworkPolicyRuleConstSharedPtr>& rules) {
    if (initialized_ && rules.empty() != rules_.empty()) {
      addDefaultAllowRule();
    }
    for (auto& rule : rules) {
      rules_.insert(rules_.end(), rule);
      updateFor(rule);
    }
    initialized_ = true;
  }

  // Sort by descending precedence. Within the same precedence, deny rules come first,
  // then allow rules, and pass rules last. This lets runtime pass handling jump
  // immediately, as any same-precedence allow/deny verdict has already been seen.
  void sort() {
    std::stable_sort(rules_.begin(), rules_.end(),
                     [](const PortNetworkPolicyRuleConstSharedPtr& a,
                        const PortNetworkPolicyRuleConstSharedPtr& b) {
                       return (a->precedence_ > b->precedence_) ||
                              (a->precedence_ == b->precedence_ && a->verdict_ > b->verdict_);
                     });
  }

  void prepareRuntimePasses() {
    if (!has_pass_rules_) {
      return;
    }

    uint32_t pass_precedence = 0;
    for (uint32_t idx = 0; idx < rules_.size(); idx++) {
      if (rules_[idx]->tier_last_precedence_ == 0) {
        continue;
      }

      if (rules_[idx].use_count() > 1) {
        // Pass continuation index is specific to this ordered rule set, so shared pass
        // rules must be cloned before storing the computed continuation on the rule.
        rules_[idx] = std::make_shared<PortNetworkPolicyRule>(*rules_[idx]);
      }
      auto& rule = const_cast<PortNetworkPolicyRule&>(*rules_[idx]);

      if (pass_precedence && rule.precedence_ < pass_precedence) {
        pass_precedence = 0;
      }

      if (pass_precedence && rule.tier_last_precedence_ != pass_precedence) {
        throw EnvoyException(fmt::format("PortNetworkPolicy: Inconsistent pass precedence {} != {}",
                                         rule.tier_last_precedence_, pass_precedence));
      }
      pass_precedence = rule.tier_last_precedence_;

      uint32_t pass_index = idx + 1;
      while (pass_index < rules_.size() && rules_[pass_index]->precedence_ >= pass_precedence) {
        pass_index++;
      }
      rule.pass_index_ = pass_index;
    }
  }

  bool empty() const { return rules_.empty(); }

  template <typename F> RuleVerdict forEachRule(bool can_short_circuit, F&& func) const {
    RuleVerdict verdict = RuleVerdict::None;
    uint32_t verdict_precedence = 0;

    // Uninitialized rules match nothing
    ASSERT(initialized_, "uninitialized rules");
    if (!initialized_) {
      return verdict;
    }

    // Empty set matches any payload from anyone
    if (empty()) {
      return RuleVerdict::Allow;
    }

    for (uint32_t idx = 0; idx < rules_.size();) {
      const auto& rule = rules_[idx];

      // lower precedence rules are skipped if there is a verdict
      if (verdict != RuleVerdict::None && rule->precedence_ < verdict_precedence) {
        break;
      }
      auto rule_verdict = func(*rule);
      if (rule_verdict == RuleVerdict::Pass) {
        ASSERT(rule->pass_index_, "matching pass rule must have a continuation index");
        if (verdict == RuleVerdict::None || verdict_precedence < rule->precedence_) {
          idx = rule->pass_index_;
          continue;
        }
      } else if (rule_verdict != RuleVerdict::None) {
        verdict = rule_verdict;
        verdict_precedence = rule->precedence_;

        // Short-circuit on the first deny or on first allow if no rules have HeaderMatches
        if (rule_verdict == RuleVerdict::Deny || can_short_circuit) {
          return verdict;
        }
      }
      idx++;
    }
    return verdict;
  }

  // forEachRulePred return a RuleVerdict by scanning through all rules, getting the verdict for
  // each rule and checking if the predicate matches. Returns RuleVerdict::Allow if any rule allows
  // the traffic, even if the predicate returns false. Stops as soon as the first rule returns
  // 'true' for the predicate.
  // This is used to the applicable TLS context from the rules, if any. Note that in this use 'pred'
  // has side effects, but it is idempotent.
  template <typename F, typename P> RuleVerdict forEachRulePred(F&& get_verdict, P&& pred) const {
    RuleVerdict verdict = RuleVerdict::None;
    uint32_t verdict_precedence = 0;

    // Uninitialized rules match nothing
    ASSERT(initialized_, "uninitialized rules");
    if (!initialized_) {
      return verdict;
    }

    // Empty set matches any payload from anyone
    if (empty()) {
      return RuleVerdict::Allow;
    }

    for (uint32_t idx = 0; idx < rules_.size();) {
      const auto& rule = rules_[idx];

      auto rule_verdict = get_verdict(*rule);
      switch (rule_verdict) {
      case RuleVerdict::Pass:
        ASSERT(rule->pass_index_, "matching pass rule must have a continuation index");
        if (verdict == RuleVerdict::None || verdict_precedence < rule->precedence_) {
          idx = rule->pass_index_;
          continue;
        }
        break;
      case RuleVerdict::Deny:
        // return higher precedence allow verdict if any.
        if (verdict != RuleVerdict::None && verdict_precedence > rule->precedence_) {
          return verdict;
        }
        return rule_verdict;
      case RuleVerdict::Allow:
        if (pred(*rule)) {
          // Return after the first allow verdict that fulfills the predicate
          return rule_verdict;
        }
        // store highest precedence allow verdict that does not fulfill the predicate
        if (verdict == RuleVerdict::None) {
          verdict = rule_verdict;
          verdict_precedence = rule->precedence_;
        }
        break;
      case RuleVerdict::None:
        break;
      }
      idx++;
    }
    return verdict;
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id,
                         Envoy::Http::RequestHeaderMap& headers,
                         Cilium::AccessLog::Entry& log_entry,
                         const SelectorVersion selector_version) const {
    auto verdict = forEachRule(can_short_circuit_, [&](const auto& rule) {
      return rule.getVerdict(proxy_id, remote_id, headers, log_entry, selector_version);
    });

    ENVOY_LOG(trace,
              "Cilium L7 PortNetworkPolicyRules(proxy_id: {}, remote_id: {}, headers: {}): {}",
              proxy_id, remote_id, headers, verdict);
    return verdict;
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
                         const SelectorVersion selector_version) const {
    auto verdict = forEachRule(true, [&](const auto& rule) {
      return rule.getVerdict(proxy_id, remote_id, sni, selector_version);
    });

    ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(proxy_id: {}, remote_id: {}, sni: {}): {}",
              proxy_id, remote_id, sni, verdict);
    return verdict;
  }

  RuleVerdict useProxylib(uint16_t proxy_id, uint32_t remote_id, std::string& l7_proto,
                          const SelectorVersion selector_version) const {
    return forEachRule(true, [&](const auto& rule) {
      return rule.useProxylib(proxy_id, remote_id, l7_proto, selector_version);
    });
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id,
                         const envoy::config::core::v3::Metadata& metadata,
                         const SelectorVersion selector_version) const {
    auto verdict = forEachRule(true, [&](const auto& rule) {
      return rule.getVerdict(proxy_id, remote_id, metadata, selector_version);
    });

    ENVOY_LOG(trace,
              "Cilium L7 PortNetworkPolicyRules(proxy_id: {}, remote_id: {}, metadata: {}): {}",
              proxy_id, remote_id, metadata.DebugString(), verdict);

    return verdict;
  }

  RuleVerdict getServerTlsContext(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
                                  Ssl::ContextSharedPtr& tls_ctx, const Ssl::ContextConfig*& config,
                                  const SelectorVersion selector_version) const {
    tls_ctx = nullptr;
    return forEachRulePred(
        [&](const auto& rule) {
          return rule.getVerdict(proxy_id, remote_id, sni, selector_version);
        },
        [&](const auto& rule) { return rule.getServerTlsContext(tls_ctx, config); });
  }

  RuleVerdict getClientTlsContext(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
                                  Ssl::ContextSharedPtr& tls_ctx, const Ssl::ContextConfig*& config,
                                  const SelectorVersion selector_version) const {
    tls_ctx = nullptr;
    return forEachRulePred(
        [&](const auto& rule) {
          return rule.getVerdict(proxy_id, remote_id, sni, selector_version);
        },
        [&](const auto& rule) { return rule.getClientTlsContext(tls_ctx, config); });
  }

  void toString(int indent, std::string& res) const {
    res.append(indent - 2, ' ').append("- rules:\n");
    for (const auto& rule : rules_) {
      rule->toString(indent + 2, res);
    }
    if (!can_short_circuit_) {
      res.append(indent, ' ').append(fmt::format("can_short_circuit: false\n"));
    }
  }

  bool hasHttpRules() const {
    for (const auto& rule : rules_) {
      if (rule->hasHttpRules()) {
        return true;
      }
    }
    return false;
  }

  bool hasOnlyPassRules() const {
    return !rules_.empty() &&
           std::ranges::all_of(rules_, [](const auto& rule) { return rule->pass_index_ != 0; });
  }

  // ordered set of rules as a sorted vector
  std::vector<PortNetworkPolicyRuleConstSharedPtr> rules_; // Allowed if empty.
  bool can_short_circuit_{true};
  bool has_pass_rules_{false};
  bool initialized_{false};
};

// PortRangeCompare is used for as std::less replacement for port range keys.
//
// All port ranges in the map have non-overlapping keys, which allows total ordering needed for
// ordered map containers. When inserting new ranges, any range overlap will be flagged as a
// "duplicate" entry, as overlapping keys are considered equal (as neither is strictly less than the
// other given this comparison predicate).
// On lookups we'll set both ends of the port range to the same port number, which will find the one
// range that it overlaps with, if one exists.
using PortRange = std::pair<uint16_t, uint16_t>;
struct PortRangeCompare {
  bool operator()(const PortRange& a, const PortRange& b) const {
    // return true if range 'a.first - a.second' is below range 'b.first - b.second'.
    return a.second < b.first;
  }
};

// PolicySnapshot is keyed by port ranges, and contains a list of PortNetworkPolicyRules's
// applicable to this range. A list is needed as rules may come from multiple sources (e.g.,
// resulting from use of named ports and numbered ports in Cilium Network Policy at the same time).
class PolicySnapshot : public absl::btree_map<PortRange, PortNetworkPolicyRules, PortRangeCompare> {
public:
  using absl::btree_map<PortRange, PortNetworkPolicyRules, PortRangeCompare>::btree_map;
};

namespace {

const PortNetworkPolicyRules* findPortRules(const PolicySnapshot& map, uint16_t port) {
  // Look up with an exact port first, then fall back to the wildcard port (0). If policy is found
  // with the exact port, then the returned policy also contains all the wildcard port rules, so we
  // do not need to perform a separate wildcard port policy lookup. If no policy is defined for the
  // given port, then the wildcard port policy, consisting just of the wildcard port rules, is used,
  // if one exists.
  //
  // On lookups we'll set both ends of the port range to the same port number, which will find the
  // one range that it overlaps with in the map, if one exists (ref. PortRangeCompare definition).
  if (const auto it = map.find({port, port}); it != map.cend()) {
    return &it->second;
  }
  if (const auto wildcard = map.find({0, 0}); wildcard != map.cend()) {
    return &wildcard->second;
  }
  return nullptr;
}

} // namespace

PortPolicy::PortPolicy(const PolicySnapshot& map, uint16_t port, SelectorVersion selector_version)
    : port_rules_(findPortRules(map, port)),
      has_http_rules_(port_rules_ && port_rules_->hasHttpRules()),
      selector_version_(selector_version) {}

bool PortPolicy::useProxylib(uint16_t proxy_id, uint32_t remote_id, std::string& l7_proto) const {
  if (port_rules_) {
    auto verdict = port_rules_->useProxylib(proxy_id, remote_id, l7_proto, selector_version_);
    if (verdict == RuleVerdict::Allow) {
      return true;
    }
  }
  l7_proto = "";
  return false;
}

bool PortPolicy::allowed(uint16_t proxy_id, uint32_t remote_id,
                         Envoy::Http::RequestHeaderMap& headers,
                         Cilium::AccessLog::Entry& log_entry) const {
  // Network layer policy has already been enforced. If there are no http rules, then there is
  // nothing to do.
  if (!has_http_rules_) {
    return true;
  }
  if (!port_rules_) {
    return false;
  }
  return port_rules_->getVerdict(proxy_id, remote_id, headers, log_entry, selector_version_) ==
         RuleVerdict::Allow;
}

bool PortPolicy::allowed(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni) const {
  if (!port_rules_) {
    return false;
  }
  return port_rules_->getVerdict(proxy_id, remote_id, sni, selector_version_) == RuleVerdict::Allow;
}

bool PortPolicy::allowed(uint16_t proxy_id, uint32_t remote_id,
                         const envoy::config::core::v3::Metadata& metadata) const {
  if (!port_rules_) {
    return false;
  }
  return port_rules_->getVerdict(proxy_id, remote_id, metadata, selector_version_) ==
         RuleVerdict::Allow;
}

Ssl::ContextSharedPtr PortPolicy::getServerTlsContext(uint16_t proxy_id, uint32_t remote_id,
                                                      absl::string_view sni,
                                                      const Ssl::ContextConfig*& config,
                                                      bool& raw_socket_allowed) const {
  Ssl::ContextSharedPtr tls_ctx;

  config = nullptr;
  raw_socket_allowed = false;
  if (port_rules_) {
    auto verdict = port_rules_->getServerTlsContext(proxy_id, remote_id, sni, tls_ctx, config,
                                                    selector_version_);
    raw_socket_allowed = verdict == RuleVerdict::Allow && tls_ctx == nullptr && config == nullptr;
  }
  return tls_ctx;
}

Ssl::ContextSharedPtr PortPolicy::getClientTlsContext(uint16_t proxy_id, uint32_t remote_id,
                                                      absl::string_view sni,
                                                      const Ssl::ContextConfig*& config,
                                                      bool& raw_socket_allowed) const {
  Ssl::ContextSharedPtr tls_ctx;

  config = nullptr;
  raw_socket_allowed = false;
  if (port_rules_) {
    auto verdict = port_rules_->getClientTlsContext(proxy_id, remote_id, sni, tls_ctx, config,
                                                    selector_version_);
    raw_socket_allowed = verdict == RuleVerdict::Allow && tls_ctx == nullptr && config == nullptr;
  }
  return tls_ctx;
}

namespace {
// Ranges overlap when one is not completely below or above the other
bool inline rangesOverlap(const PortRange& a, const PortRange& b) {
  // !(a.second < b.first || a.first > b.second)
  return a.second >= b.first && a.first <= b.second;
}
} // namespace

class PortNetworkPolicy : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicy(const NetworkPolicyMapImpl& parent,
                    const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicy>& rules,
                    const ResourceMapOverlay* resource_map) {
    for (const auto& rule : rules) {
      // Only TCP supported for HTTP
      if (rule.protocol() == envoy::config::core::v3::SocketAddress::TCP) {
        // Port may be zero, which matches any port.
        uint16_t port = rule.port();
        // End port may be zero, which means no range
        uint16_t end_port = rule.end_port();
        if (end_port < port) {
          if (end_port) {
            throw EnvoyException(fmt::format(
                "PortNetworkPolicy: Invalid port range, end port is less than start port {}-{}",
                port, end_port));
          }
          end_port = port;
        }

        if (port == 0) {
          if (end_port > 0) {
            throw EnvoyException(fmt::format(
                "PortNetworkPolicy: Invalid port range including the wildcard zero port {}-{}",
                port, end_port));
          }
        }

        ENVOY_LOG(trace,
                  "Cilium L7 PortNetworkPolicy(): installing TCP policy for "
                  "port range {}-{}",
                  port, end_port);

        auto rule_range = std::make_pair(port, end_port);
        auto pair = rules_.emplace(rule_range, PortNetworkPolicyRules{});
        auto it = pair.first;
        if (!pair.second) {
          ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): new entry [{}-{}] overlaps with [{}-{}]",
                    port, end_port, it->first.first, it->first.second);
          // Explicitly manage overlapping ranges by breaking them up.
          //
          // rules_ has the breaked up, non-overlapping ranges in order.
          //
          // While iterating through all the existing overlapping ranges:
          // - add new ranges when there are any gaps in the existing ranges (for the new range)
          // - split existing ranges if they are only partially overlapping with the new range
          // Then, as a separate step:
          // - add new rules to all of the (disjoint, ordered) ranges covered by the new range

          // The new range can overlap with multiple entries in the map, current iterator can
          // point to any one of them. Find the first entry the new entry overlaps with.
          auto last_overlap = it;
          while (it != rules_.begin()) {
            last_overlap = it;
            it--;
            if (!rangesOverlap(it->first, rule_range)) {
              break;
            }
          }
          it = last_overlap; // Move back up to the frontmost overlapping entry

          // absl::btree_map manipulation operations invalidate iterators, so we keep the range
          // (the map key) of the first overlapping entry in 'start_range' to be able to locate
          // the first range that needs the new rules after all the overlaps have been resolved.
          // 'start_key' is updated as needed below.
          auto start_range = it->first;

          // split the current entry due to partial overlap in the beginning?
          // For example, if the current entry is 80-8080 and we are adding 4040-9999,
          // the current entry should be split to two ranges 80-4039 and 4040-8080,
          // both of which should retain their current rules, but new rules should only be
          // added to the 2nd half covered by the new range 4040-9999.
          if (port > start_range.first) {
            RELEASE_ASSERT(port <= start_range.second, "non-overlapping range");
            auto rules = it->second;
            PortRange range1 = start_range;
            range1.second = port - 1;
            PortRange range2 = start_range;
            range2.first = port;

            rules_.erase(it);
            auto pr1 = rules_.insert({range1, rules});
            RELEASE_ASSERT(pr1.second, "Range split failed 1 begin");
            auto pr2 = rules_.insert({range2, rules});
            RELEASE_ASSERT(pr2.second, "Range split failed 2 begin");
            it = pr2.first;          // update current iterator
            start_range = it->first; // update the start range
          }

          // scan the range of the new rule, filling the gaps with new (partial) ranges
          for (; it != rules_.end() && port <= end_port && end_port >= it->first.first; it++) {
            auto range = it->first;
            // create a new entry below the current one?
            if (port < range.first) {
              auto new_range = std::make_pair(port, std::min(end_port, uint16_t(range.first - 1)));
              auto new_pair = rules_.emplace(new_range, PortNetworkPolicyRules{});
              RELEASE_ASSERT(new_pair.second,
                             "duplicate entry when explicitly adding a new range!");
              // update the start range if a new start entry was added, which can happen only at the
              // beginning of this loop when port is still at the beginning of the rule range being
              // added.
              if (port == rule_range.first) {
                start_range = new_range;
              }
              // absl::btree_map insertion invalidates iterators, have to update.
              it = ++new_pair.first; // one past the new entry
              if (end_port < range.first) {
                // done
                break;
              }
              // covered upto range.first-1, continue from range.first
              port = range.first;
            }
            RELEASE_ASSERT(port == range.first, "port should match the start of the current range");
            // split the current range into two due to partial overlap in the end?
            if (end_port < range.second) {
              auto rules = it->second;
              PortRange range1 = it->first;
              range1.second = end_port;
              PortRange range2 = it->first;
              range2.first = end_port + 1;

              rules_.erase(it);
              auto pr1 = rules_.insert({range1, rules});
              RELEASE_ASSERT(pr1.second, "Range split failed 1 end");
              auto pr2 = rules_.insert({range2, rules});
              RELEASE_ASSERT(pr2.second, "Range split failed 2 end");
              it = pr2.first;      // one past the end of range
              port = end_port + 1; // one past the end
              break;
            } else {
              // current entry completely covered by the new range, skip to the next
              port = range.second + 1;
            }
          }
          // create a new entry covering the end?
          if (port <= end_port) {
            auto new_range = std::make_pair(port, end_port);
            auto new_pair = rules_.emplace(new_range, PortNetworkPolicyRules{});
            RELEASE_ASSERT(new_pair.second,
                           "duplicate entry at end when explicitly adding a new range!");
            it = ++new_pair.first;
          }
          // make 'it' point to the first overlapping entry for the rule updates to follow
          it = rules_.find(start_range);
          RELEASE_ASSERT(it != rules_.end(), "first overlapping entry not found");
        }
        // Add rules to all the overlapping entries
        bool singular = rule_range.first == rule_range.second;
        for (; it != rules_.end() && rangesOverlap(it->first, rule_range); it++) {
          auto range = it->first;
          auto& rules = it->second;
          ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): Adding rules for [{}-{}] to [{}-{}]",
                    rule_range.first, rule_range.second, range.first, range.second);
          if (singular) {
            // Exact port rules go to the front of the list.
            // This gives precedence for trivial range rules for proxylib parser
            // and TLS context selection.
            // prepend() inserts each rule at begin() while iterating forward,
            // so the relative order of rules from this batch is reversed. This
            // is harmless: equal-precedence rules are evaluated as alternatives
            // (stable sort only affects presentation/debug ordering).
            rules.prepend(parent, rule.rules(), resource_map);
          } else {
            // Rules with a non-trivial range go to the back of the list
            rules.append(parent, rule.rules(), resource_map);
          }
        }
      } else {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): NOT installing non-TCP policy");
      }
    }

    // Apply wildcard port rules to all ranges
    const PortNetworkPolicyRules* wildcard_rules = nullptr;
    for (auto& [port_range, rules] : rules_) {
      if (port_range.first == 0) {
        wildcard_rules = &rules;
        continue;
      }
      if (!wildcard_rules) {
        break;
      }
      rules.appendRules(wildcard_rules->rules_);
    }

    bool have_passes = false;

    // sort rules on each non-overlapping port range into descending precedence
    // port ranges themselves remain in the sorted order.
    // This way we can efficiently find the list of rules applicable to any given port,
    // and then process those rules in the order of decreasing precedence.
    for (auto& pair : rules_) {
      pair.second.sort();
      if (pair.second.has_pass_rules_) {
        have_passes = true;
      }
    }

    if (have_passes) {
      for (auto& [port_range, rules] : rules_) {
        (void)port_range;
        rules.prepareRuntimePasses();
      }

      // Pass-only ranges do not yield a final verdict, but keeping them would make
      // higher-level L7 checks treat the range as "no L7 rules" and allow by default.
      for (auto it = rules_.begin(); it != rules_.end();) {
        if (it->second.hasOnlyPassRules()) {
          it = rules_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  const PortPolicy findPortPolicy(uint16_t port, const SelectorVersion selector_version) const {
    return PortPolicy(rules_, port, selector_version);
  }

  void toString(int indent, std::string& res) const {
    if (rules_.empty()) {
      res.append(indent, ' ').append("rules: []\n");
    } else {
      res.append(indent, ' ').append("rules:\n");
      for (const auto& entry : rules_) {
        res.append(indent + 2, ' ')
            .append(fmt::format("[{}-{}]:\n", entry.first.first, entry.first.second));
        entry.second.toString(indent + 4, res);
      }
    }
  }

  PolicySnapshot rules_;
  bool has_http_rules_ = false;
};

// Construction is single-threaded, but all other use is from multiple worker threads using const
// methods.
class PolicyInstanceImpl : public PolicyInstance {
public:
  friend class NetworkPolicyMapImpl;
  PolicyInstanceImpl(const NetworkPolicyMapImpl& parent, uint64_t hash,
                     const cilium::NetworkPolicy& proto,
                     const PolicyStreamStateConstSharedPtr& policy_stream_state,
                     const ResourceMapOverlay* resource_map)
      : endpoint_id_(proto.endpoint_id()), hash_(hash), policy_proto_(proto), endpoint_ips_(proto),
        parent_(parent), policy_stream_state_(policy_stream_state),
        ingress_(parent, policy_proto_.ingress_per_port_policies(), resource_map),
        egress_(parent, policy_proto_.egress_per_port_policies(), resource_map) {}

  bool allowed(bool ingress, uint16_t proxy_id, uint32_t remote_id, uint16_t port,
               Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry) const override {
    const auto port_policy = findPortPolicy(ingress, port);
    if (!port_policy.hasHttpRules()) {
      return true;
    }
    return port_policy.allowed(proxy_id, remote_id, headers, log_entry);
  }

  bool allowed(bool ingress, uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
               uint16_t port) const override {
    const auto port_policy = findPortPolicy(ingress, port);
    return port_policy.allowed(proxy_id, remote_id, sni);
  }

  const PortPolicy findPortPolicy(bool ingress, uint16_t port) const override {
    const auto selector_version = policy_stream_state_->version();
    return ingress ? ingress_.findPortPolicy(port, selector_version)
                   : egress_.findPortPolicy(port, selector_version);
  }

  bool useProxylib(bool ingress, uint16_t proxy_id, uint32_t remote_id, uint16_t port,
                   std::string& l7_proto) const override {
    const auto port_policy = findPortPolicy(ingress, port);
    return port_policy.useProxylib(proxy_id, remote_id, l7_proto);
  }

  uint32_t getEndpointID() const override { return endpoint_id_; }

  const IpAddressPair& getEndpointIPs() const override { return endpoint_ips_; }

  std::string string() const override {
    std::string res;
    res.append("ingress:\n");
    ingress_.toString(2, res);
    res.append("egress:\n");
    egress_.toString(2, res);
    return res;
  }

  void tlsWrapperMissingPolicyInc() const override { parent_.tlsWrapperMissingPolicyInc(); }

public:
  uint32_t endpoint_id_;
  uint64_t hash_;
  const cilium::NetworkPolicy policy_proto_;
  const IpAddressPair endpoint_ips_;

private:
  const NetworkPolicyMapImpl& parent_;
  const PolicyStreamStateConstSharedPtr policy_stream_state_;
  const PortNetworkPolicy ingress_;
  const PortNetworkPolicy egress_;
};

template <class EndpointIps> std::string endpointIpsForLog(const EndpointIps& endpoint_ips) {
  std::string formatted = "[";
  bool first = true;
  for (const auto& endpoint_ip : endpoint_ips) {
    if (!first) {
      formatted += ", ";
    }
    formatted += endpoint_ip;
    first = false;
  }
  formatted += "]";
  return formatted;
}

std::string describePolicyResourceForLog(absl::string_view resource_name,
                                         const std::shared_ptr<const PolicyInstanceImpl>& policy) {
  ASSERT(policy != nullptr, "policy resource description requires a policy");
  return fmt::format("policy resource '{}' (endpoint_id {}, endpoint_ips {})", resource_name,
                     policy->endpoint_id_, endpointIpsForLog(policy->policy_proto_.endpoint_ips()));
}

std::string describePolicyResourceForLog(absl::string_view resource_name,
                                         const cilium::NetworkPolicy& policy) {
  return fmt::format("policy resource '{}' (endpoint_id {}, endpoint_ips {})", resource_name,
                     policy.endpoint_id(), endpointIpsForLog(policy.endpoint_ips()));
}

std::string
ResourceMap::findPolicyResourceName(const std::shared_ptr<const PolicyInstanceImpl>& policy) const {
  if (policy == nullptr) {
    return {};
  }
  for (const auto& [resource_name, resource_key] : *this) {
    const auto* policy_entry = resource_key.policyResourceEntry();
    if (policy_entry != nullptr && policy_entry->policy == policy) {
      return resource_name;
    }
  }
  return {};
}

std::string ResourceMapOverlay::findPolicyResourceName(
    const std::shared_ptr<const PolicyInstanceImpl>& policy) const {
  if (policy == nullptr) {
    return {};
  }
  for (const auto& [resource_name, resource_key] : upserts_) {
    const auto* policy_entry = resource_key.policyResourceEntry();
    if (policy_entry != nullptr && policy_entry->policy == policy) {
      return resource_name;
    }
  }
  if (base_ == nullptr) {
    return {};
  }
  for (const auto& [resource_name, resource_key] : *base_) {
    if (removed_.contains(resource_name)) {
      continue;
    }
    const auto* policy_entry = resource_key.policyResourceEntry();
    if (policy_entry != nullptr && policy_entry->policy == policy) {
      return resource_name;
    }
  }
  return {};
}

std::string
ResourceMapOverlay::describeExistingResourceKey(const std::string& key,
                                                const PolicyMapSnapshot& policy_map) const {
  const auto* entry = findEntry(key);
  if (entry == nullptr) {
    return fmt::format("resource key '{}'", key);
  }
  if (entry->selectorResourceEntry() != nullptr) {
    return fmt::format("selector resource '{}'", key);
  }
  if (const auto* policy_entry = entry->policyResourceEntry();
      policy_entry != nullptr && policy_entry->policy != nullptr) {
    return describePolicyResourceForLog(key, policy_entry->policy);
  }
  if (!entry->isPolicyEndpointIpEntry()) {
    return fmt::format("resource key '{}'", key);
  }

  auto policy_it = policy_map.find(key);
  if (policy_it == policy_map.end()) {
    return fmt::format("endpoint IP alias '{}'", key);
  }

  const auto& policy = policy_it->second;
  const auto resource_name = findPolicyResourceName(policy);
  if (!resource_name.empty()) {
    return fmt::format("endpoint IP alias '{}' owned by {}", key,
                       describePolicyResourceForLog(resource_name, policy));
  }

  return fmt::format("endpoint IP alias '{}' owned by endpoint_id {} with endpoint_ips {}", key,
                     policy->endpoint_id_, endpointIpsForLog(policy->policy_proto_.endpoint_ips()));
}

void ResourceMap::erasePolicyResource(PolicyMapSnapshot& policy_map,
                                      const std::string& resource_name,
                                      const std::shared_ptr<const PolicyInstanceImpl>& policy) {
  ASSERT(policy != nullptr, "policy resource key must carry a policy");
  for (const auto& endpoint_ip : policy->policy_proto_.endpoint_ips()) {
    policy_map.erase(endpoint_ip);
    erase(endpoint_ip);
  }
  erase(resource_name);
}

void ResourceMapOverlay::erasePolicyResource(
    PolicyMapSnapshot& policy_map, const std::string& resource_name,
    const std::shared_ptr<const PolicyInstanceImpl>& policy) {
  ASSERT(policy != nullptr, "policy resource key must carry a policy");
  for (const auto& endpoint_ip : policy->policy_proto_.endpoint_ips()) {
    policy_map.erase(endpoint_ip);
    erase(endpoint_ip);
  }
  erase(resource_name);
}

namespace {

bool policyUsesSelectors(const cilium::NetworkPolicy& policy) {
  for (const auto& port_policy : policy.ingress_per_port_policies()) {
    if (std::ranges::any_of(port_policy.rules(),
                            [](const auto& rule) { return rule.selectors_size() > 0; })) {
      return true;
    }
  }
  for (const auto& port_policy : policy.egress_per_port_policies()) {
    if (std::ranges::any_of(port_policy.rules(),
                            [](const auto& rule) { return rule.selectors_size() > 0; })) {
      return true;
    }
  }
  return false;
}

} // namespace

// Common base constructor
// This is used directly for testing with a file-based subscription
NetworkPolicyMap::NetworkPolicyMap(Server::Configuration::FactoryContext& context, bool subscribe,
                                   bool use_delta_xds)
    : context_(context.serverFactoryContext()) {
  impl_ = std::make_shared<NetworkPolicyMapImpl>(context, use_delta_xds);

  if (subscribe) {
    impl_->subscribe();
  }
}

NetworkPolicyMap::~NetworkPolicyMap() {
  ENVOY_LOG(debug,
            "Cilium L7 NetworkPolicyMap: posting NetworkPolicyMapImpl deletion to main thread");

  // Policy map destruction happens when the last listener with the Cilium bpf_metadata listener
  // filter has drained out and is finally removed, and last connection of the old listener is
  // closed. This does not happen if new listener(s) with references to policy map are created in
  // the meanwhile.
  //
  // Destruction of the NetworkPolicyMapImpl must be made from the main thread to ensure integrity
  // of SDS subscription management. Since this can be called from a worker thread of the last
  // connection we must post the destruction to the main thread dispatcher.
  //
  // Move the NetworkPolicyMapImpl to the lambda capture so that it goes out of scope and gets
  // deleted in the main thread.

  context_.mainThreadDispatcher().post([impl = std::move(impl_)]() {});
}

bool NetworkPolicyMap::exists(const std::string& endpoint_policy_name) const {
  return impl_->getPolicyInstanceImpl(endpoint_policy_name);
}

bool NetworkPolicyMap::useDeltaXds() const { return impl_->useDeltaXds(); }
void NetworkPolicyMap::setUseDeltaXds(bool use_delta_xds) const {
  impl_->setUseDeltaXds(use_delta_xds);
}

void NetworkPolicyMap::startSubscriptionForTest(
    std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
  impl_->subscribe(std::move(subscription));
}

void NetworkPolicyMap::startManagedSubscriptionForTest() {
  impl_->startManagedSubscriptionForTest();
}

void NetworkPolicyMap::setSubscriptionFactoryForTest(SubscriptionFactoryForTest factory) {
  impl_->setSubscriptionFactoryForTest(std::move(factory));
}

void NetworkPolicyMap::onSubscriptionConnectedForTest() { impl_->onSubscriptionConnectedForTest(); }

void NetworkPolicyMap::onSubscriptionTransportCloseForTest() {
  impl_->onSubscriptionTransportCloseForTest();
}

bool NetworkPolicyMap::subscriptionUseDeltaXdsForTest() const {
  return impl_->subscriptionUseDeltaXdsForTest();
}

bool NetworkPolicyMap::subscriptionConnectedForTest() const {
  return impl_->subscriptionConnectedForTest();
}

Envoy::Config::SubscriptionCallbacks& NetworkPolicyMap::subscriptionCallbacksForTest() const {
  return *impl_;
}

PolicyStats& NetworkPolicyMap::statsForTest() const { return impl_->stats_; }

void NetworkPolicyMap::resetStreamForTest() { impl_->resetStreamForTest(); }

PolicyInstanceConstSharedPtr
NetworkPolicyMap::getPolicyInstanceSharedForTest(const std::string& endpoint_policy_name) const {
  return impl_->getPolicyInstanceSharedImpl(endpoint_policy_name);
}

uint64_t
NetworkPolicyMap::policySelectorStreamGenerationForTest(const PolicyInstance& policy) const {
  return impl_->policySelectorStreamGenerationForTestImpl(policy);
}

SelectorVersion NetworkPolicyMap::policySelectorVersionForTest(const PolicyInstance& policy) const {
  return impl_->policySelectorVersionForTestImpl(policy);
}

NetworkPolicyMapImpl::NetworkPolicyMapImpl(Server::Configuration::FactoryContext& context,
                                           bool use_delta_xds)
    : desired_use_delta_xds_(use_delta_xds), subscription_use_delta_xds_(use_delta_xds),
      context_(context.serverFactoryContext()), map_ptr_(nullptr),
      npds_stats_scope_(context_.serverScope().createScope("cilium.npds.")),
      policy_stats_scope_(context_.serverScope().createScope("cilium.policy.")),
      init_target_(fmt::format("Cilium Network Policy subscription start"),
                   [this]() {
                     // production subscription is allowed to start from now on
                     subscription_should_start_ = true;
                     startSubscription();
                     // Allow listener init to continue before network policy updates are received
                     init_target_.ready();
                   }),
      transport_factory_context_(
          std::make_shared<Server::Configuration::TransportSocketFactoryContextImpl>(
              context_, *npds_stats_scope_,
              context_.messageValidationContext().dynamicValidationVisitor())),
      stats_{ALL_CILIUM_POLICY_STATS(POOL_COUNTER(*policy_stats_scope_),
                                     POOL_HISTOGRAM(*policy_stats_scope_))} {
  // Use listener init manager for subscription initialization
  context.initManager().add(init_target_);

  // Allocate an initial policy map so that the map pointer is never a nullptr
  store(new PolicyMapSnapshot());
  ENVOY_LOG(trace, "NetworkPolicyMapImpl({}) created.", instance_id_);

  if (context_.admin().has_value()) {
    ENVOY_LOG(debug, "Registering NetworkPolicies to config tracker");
    config_tracker_entry_ = context_.admin()->getConfigTracker().add(
        "networkpolicies", [this](const Matchers::StringMatcher& name_matcher) {
          return dumpNetworkPolicyConfigs(name_matcher);
        });
    RELEASE_ASSERT(config_tracker_entry_, "");
  }
}

// NetworkPolicyMapImpl destructor must only be called from the main thread.
NetworkPolicyMapImpl::~NetworkPolicyMapImpl() {
  ENVOY_LOG(debug, "Cilium L7 NetworkPolicyMapImpl({}): NetworkPolicyMap is deleted NOW!",
            instance_id_);
  delete load();
}

void NetworkPolicyMapImpl::subscribe() {
  subscription_connected_ = false;
  subscription_use_delta_xds_ = desired_use_delta_xds_;
  ++subscription_id_;

  if (subscription_factory_for_test_) {
    subscription_ = subscription_factory_for_test_(subscription_use_delta_xds_);
    if (subscription_should_start_) {
      startSubscription();
    }
    return;
  }

  auto on_transport_close = [weak_this = weak_from_this(), id = subscription_id_]() {
    if (auto shared_this = weak_this.lock()) {
      shared_this->onSubscriptionTransportClosed(id);
    }
  };
  auto on_transport_established = [weak_this = weak_from_this(), id = subscription_id_]() {
    if (auto shared_this = weak_this.lock()) {
      shared_this->onSubscriptionTransportEstablished(id);
    }
  };

  if (subscription_use_delta_xds_) {
    subscription_ = Cilium::subscribe(
        "type.googleapis.com/cilium.NetworkPolicyResource", context_, *npds_stats_scope_, *this,
        std::make_shared<NetworkPolicyResourceDecoder>(), subscription_use_delta_xds_,
        std::chrono::milliseconds(0), std::move(on_transport_established),
        std::move(on_transport_close));
  } else {
    subscription_ =
        Cilium::subscribe("type.googleapis.com/cilium.NetworkPolicy", context_, *npds_stats_scope_,
                          *this, std::make_shared<NetworkPolicyDecoder>(),
                          subscription_use_delta_xds_, std::chrono::milliseconds(0),
                          std::move(on_transport_established), std::move(on_transport_close));
  }

  if (subscription_should_start_) {
    startSubscription();
  }
}

void NetworkPolicyMapImpl::reopenIpcache() {
  // Get ipcache singleton only if it was successfully created previously.
  // Cilium agent re-creates IP cache on restart, and the first accepted update on
  // the new stream must reopen it before workers enforce refreshed identities.
  IpCacheSharedPtr ipcache = IpCache::getIpCache(context_);
  if (ipcache) {
    ENVOY_LOG(info, "Reopening ipcache on new stream");
    ipcache->open();
  }
}

std::shared_ptr<const PolicyInstanceImpl> NetworkPolicyMapImpl::createOrReusePolicy(
    const std::string& resource_name, const cilium::NetworkPolicy& config,
    const PolicyStreamStateConstSharedPtr& policy_stream_state, const ResourceMap& resource_map,
    const ResourceMapOverlay* pending_resource_map) {
  const uint64_t new_hash = MessageUtil::hash(config);
  auto it = resource_map.find(resource_name);
  if (it != resource_map.cend()) {
    const auto* old_policy_entry = it->second.policyResourceEntry();
    if (old_policy_entry == nullptr) {
      return std::make_shared<const PolicyInstanceImpl>(*this, new_hash, config,
                                                        policy_stream_state, pending_resource_map);
    }
    const auto& old_policy = old_policy_entry->policy;
    if (old_policy && old_policy->hash_ == new_hash &&
        Protobuf::util::MessageDifferencer::Equals(old_policy->policy_proto_, config) &&
        !(pending_resource_map && policyUsesSelectors(config))) {
      ENVOY_LOG(trace, "New policy is equal to old one, not updating.");
      return old_policy;
    }
  }

  return std::make_shared<const PolicyInstanceImpl>(*this, new_hash, config, policy_stream_state,
                                                    pending_resource_map);
}

SelectorHandle NetworkPolicyMapImpl::createOrReuseSelector(const std::string& resource_name,
                                                           const cilium::Selector& config,
                                                           uint64_t update_version) {
  // Compare against the selector visible in the currently prepared update version, not just the
  // last published one. Under the single-update-in-flight VersionedMap contract, any selector
  // visible in 'update_version' is also the indefinite selector value for that candidate update.
  auto selector_value = selector_map_.find(resource_name);
  if (selector_value) {
    const auto* old_selector = selector_value->get(update_version);
    if (old_selector &&
        old_selector->size() == static_cast<size_t>(config.remote_identities_size()) &&
        std::ranges::all_of(config.remote_identities(), [&](const auto remote_identity) {
          return old_selector->contains(remote_identity);
        })) {
      return selector_value;
    }
  }

  // otherwise create a new one and insert it to the selector map.

  auto selector = new SelectorInstance();
  selector->reserve(config.remote_identities_size());
  for (const auto remote_identity : config.remote_identities()) {
    selector->emplace(remote_identity);
  }
  return selector_map_.insert(resource_name, selector);
}

void NetworkPolicyMapImpl::installNewPolicyMap(
    PolicyMapSnapshot&& new_policy_map, Init::ManagerImpl& version_init_manager,
    std::string&& version_name, const PolicyStreamStateSharedPtr& policy_stream_state) {
  // Initialize SDS secrets. We do not wait for the completion.
  version_init_manager.initialize(Init::WatcherImpl(std::move(version_name), []() {}));

  auto new_policy_map_ptr = std::make_unique<PolicyMapSnapshot>(std::move(new_policy_map));
  // Publish selector data before publishing the new policy map. New policies created above already
  // point at 'policy_stream_state', so any worker that can observe the swapped-in policy map must
  // also be able to observe the selector version those policies expect to use.
  auto new_version = selector_map_.publishNextVersion();
  if (new_version > 0) {
    policy_stream_state->publishVersion(new_version);
  }
  policy_stream_state_ = policy_stream_state;

  // old version can be GC'd once all worker threads have quiesced
  const auto* old_policy_map = exchange(new_policy_map_ptr.release());

  // Delete the old map and first-phase GC old selector versions once all worker threads have
  // entered their event queues, as this is proof that they no longer refer to the old map.
  scheduleSelectorGCAndDeferredDeletion(new_version, old_policy_map);
}

// removeInitManager must be called at the end of each policy update
void NetworkPolicyMapImpl::removeInitManager() {
  // Remove the local init manager from the transport factory context
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnull-dereference"
#endif
  transport_factory_context_->setInitManager(*static_cast<Init::Manager*>(nullptr));
#ifdef __clang__
#pragma clang diagnostic pop
#endif
}

void NetworkPolicyMapImpl::scheduleSelectorDeferredDeletion(
    DeferredDeletion<SelectorInstance>&& deferred) {
  if (deferred.empty()) {
    return;
  }
  auto deferred_owner = std::make_shared<DeferredDeletion<SelectorInstance>>(std::move(deferred));
  // The callback exists only to keep the deferred-deletion batch alive until all workers have
  // quiesced once more. The batch deletes its nodes from the closure destructor.
  runAfterAllThreads([deferred_owner]() {});
}

void NetworkPolicyMapImpl::scheduleSelectorGCAndDeferredDeletion(
    uint64_t published_version, const PolicyMapSnapshot* old_policy_map) {
  if (published_version == 0 && old_policy_map == nullptr) {
    return;
  }
  runAfterAllThreads([shared_this = shared_from_this(), published_version, old_policy_map]() {
    // Clean-up in the main thread after all worker threads have scheduled.
    // Delete the old policy map before selector GC. Old policies are the only remaining users of
    // old-stream selector versions; once the old map is gone after this quiescence point, those
    // selector versions may be unlinked and deferred for deletion.
    delete old_policy_map;
    if (published_version == 0) {
      return;
    }
    shared_this->scheduleSelectorDeferredDeletion(shared_this->selector_map_.gc(published_version));
  });
}

// onConfigUpdate parses the new network policy resources, allocates a new policy map and atomically
// swaps it in place of the old policy map. Throws if any of the 'resources' can not be
// parsed. Otherwise an OK status is returned without pausing NPDS gRPC stream, causing a new
// request (ACK) to be sent immediately, without waiting SDS secrets to be loaded.
absl::Status NetworkPolicyMapImpl::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& resources,
    const std::string& version_info) {
  subscription_connected_ = true;
  auto stream_generation = streamGeneration();
  // policy_stream_state_ gets updated on first successful update,
  // so 'is_new_stream' remains 'true' as long as the stream has not had a successful update yet.
  const bool is_new_stream = stream_generation != policy_stream_state_->streamGeneration();
  ENVOY_LOG(debug, "NetworkPolicyMapImpl::onConfigUpdate({}), {} resources, version: {}",
            instance_id_, resources.size(), version_info);
  stats_.updates_total_.inc();

  // Reopen IPcache for every new stream. Cilium agent re-creates IP cache on restart,
  // and that is also when the old stream terminates and a new one is created.
  // New security identities (e.g., for FQDN policies) only get inserted to the new IP cache,
  // so open it before the workers get a chance to enforce policy on the new IDs.
  if (is_new_stream) {
    ENVOY_LOG(info, "New NetworkPolicy stream");

    reopenIpcache();
  }

  std::string version_name = fmt::format("NetworkPolicyMap version {}", version_info);
  Init::ManagerImpl version_init_manager(version_name);
  // Set the init manager to use via the transport factory context
  // Must be set before the new network policy is parsed, as the parsed
  // SDS secrets will use this!
  transport_factory_context_->setInitManager(version_init_manager);

  const auto policy_stream_state =
      is_new_stream
          ? std::make_shared<PolicyStreamState>(stream_generation, selector_map_.getVersion())
          : policy_stream_state_;
  PolicyMapSnapshot new_policy_map;
  std::vector<std::pair<std::string, ResourceKey>> resource_entries;
  try {
    for (const auto& resource : resources) {
      const auto& config = dynamic_cast<const cilium::NetworkPolicy&>(resource.get().resource());
      const std::string& resource_name = resource.get().name();
      validateResourceName(resource_name, "Network Policy resource name");
      if (config.endpoint_ips().empty()) {
        throw EnvoyException("Network Policy has no endpoint ips");
      }
      ENVOY_LOG(debug,
                "Received Network Policy for endpoint {}, endpoint_ip {} in onConfigUpdate() "
                "version {}",
                config.endpoint_id(), config.endpoint_ips()[0], version_info);

      auto policy =
          createOrReusePolicy(resource_name, config, policy_stream_state, resource_map_, nullptr);
      if (!resource_name.empty()) {
        resource_entries.emplace_back(resource_name, ResourceKey::policyResource(policy));
      }
      for (const auto& endpoint_ip : config.endpoint_ips()) {
        ENVOY_LOG(trace, "Cilium updating or keeping network policy for endpoint {}", endpoint_ip);
        // new_policy_map is not exception safe, policy must be computed separately!
        new_policy_map.insert_or_assign(endpoint_ip, policy);
        resource_entries.emplace_back(endpoint_ip, ResourceKey::policyEndpointIp());
      }
    }
  } catch (const EnvoyException& e) {
    ENVOY_LOG(warn, "NetworkPolicy update for version {} failed: {}", version_info, e.what());
    stats_.updates_rejected_.inc();
    removeInitManager();
    throw; // re-throw
  }
  removeInitManager();

  installNewPolicyMap(std::move(new_policy_map), version_init_manager, std::move(version_name),
                      policy_stream_state);
  resource_map_.replaceWith(std::move(resource_entries));

  return absl::OkStatus();
}

absl::Status NetworkPolicyMapImpl::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
    const Protobuf::RepeatedPtrField<std::string>& removed_resources,
    const std::string& system_version_info) {
  subscription_connected_ = true;
  auto stream_generation = streamGeneration();
  // policy_stream_state_ gets updated on first successful update,
  // so 'is_new_stream' remains 'true' as long as the stream has not had a successful update yet.
  const bool is_new_stream = stream_generation != policy_stream_state_->streamGeneration();

  // first find if this is a selector-only update
  bool updates_policies = false;
  bool updates_selectors = false;
  for (const auto& removed_resource : removed_resources) {
    validateResourceName(removed_resource, "Network Policy delta removed resource name");
    auto resource_it = resource_map_.find(removed_resource);
    if (resource_it == resource_map_.end()) {
      continue;
    }
    if (resource_it->second.selectorResourceEntry()) {
      updates_selectors = true;
    } else {
      updates_policies = true;
    }
  }
  for (const auto& resource : added_resources) {
    const auto& typed_resource =
        dynamic_cast<const cilium::NetworkPolicyResource&>(resource.get().resource());
    const std::string& resource_name = resource.get().name();
    if (resource_name.empty()) {
      throw EnvoyException("Network Policy delta resource has no name");
    }
    validateResourceName(resource_name, "Network Policy delta resource name");
    switch (typed_resource.resource_case()) {
    case cilium::NetworkPolicyResource::kPolicy:
      updates_policies = true;
      break;
    case cilium::NetworkPolicyResource::kSelector:
      updates_selectors = true;
      break;
    case cilium::NetworkPolicyResource::RESOURCE_NOT_SET:
      break;
    }
  }

  ENVOY_LOG(debug,
            "NetworkPolicyMapImpl::onConfigUpdate({}), {} added resources, {} removed resources, "
            "version: {}, updates_selectors: {}, updates_policies: {}",
            instance_id_, added_resources.size(), removed_resources.size(), system_version_info,
            updates_selectors, updates_policies);
  stats_.updates_total_.inc();

  // Reopen IPcache for every new stream. Cilium agent re-creates IP cache on restart,
  // and that is also when the old stream terminates and a new one is created.
  // New security identities (e.g., for FQDN policies) only get inserted to the new IP cache,
  // so open it before the workers get a chance to enforce policy on the new IDs.
  if (is_new_stream) {
    ENVOY_LOG(info, "New NetworkPolicy stream");
    reopenIpcache();
  }
  removeInitManager();

  if (!is_new_stream && updates_selectors && !updates_policies) {
    ResourceMapOverlay pending_resource_map(resource_map_);

    try {
      const auto selector_update_version = selector_map_.prepareNextVersion();

      for (const auto& resource : removed_resources) {
        ENVOY_LOG(trace, "Cilium removing network policy selector resource {}", resource);
        const auto* resource_entry = pending_resource_map.findEntry(resource);
        if (resource_entry == nullptr) {
          ENVOY_LOG(
              debug,
              "NetworkPolicy delta removed selector resource name '{}' not found from resource map",
              resource);
          continue;
        }
        if (resource_entry->isPolicyEndpointIpEntry()) {
          throw EnvoyException(fmt::format("NetworkPolicy delta removed selector resource name "
                                           "'{}' is a policy endpoint IP alias, "
                                           "not a resource name",
                                           resource));
        }
        if (resource_entry->policyResourceEntry()) {
          throw EnvoyException(fmt::format(
              "NetworkPolicy delta removed selector resource name '{}' refers to a policy resource",
              resource));
        }
        selector_map_.clear(resource);
        pending_resource_map.erase(resource);
      }

      for (const auto& resource : added_resources) {
        const auto& typed_resource =
            dynamic_cast<const cilium::NetworkPolicyResource&>(resource.get().resource());
        if (typed_resource.resource_case() != cilium::NetworkPolicyResource::kSelector) {
          continue;
        }
        const std::string& resource_name = resource.get().name();
        pending_resource_map.eraseSelectorResourceIfPresent(resource_name);
      }

      for (const auto& resource : added_resources) {
        const auto& typed_resource =
            dynamic_cast<const cilium::NetworkPolicyResource&>(resource.get().resource());
        const std::string& resource_name = resource.get().name();

        switch (typed_resource.resource_case()) {
        case cilium::NetworkPolicyResource::kSelector: {
          ENVOY_LOG(debug,
                    "Received delta Network Policy selector resource {} in onConfigUpdate() "
                    "version {}",
                    resource_name, system_version_info);
          auto selector_handle = createOrReuseSelector(resource_name, typed_resource.selector(),
                                                       selector_update_version);
          if (!pending_resource_map.emplace(resource_name,
                                            ResourceKey::selectorResource(selector_handle))) {
            throw EnvoyException(fmt::format(
                "Network Policy delta selector update for version {} has duplicate resource key "
                "'{}' on an old stream: "
                "incoming selector resource '{}' collides with existing {}",
                system_version_info, resource_name, resource_name,
                pending_resource_map.describeExistingResourceKey(resource_name, *load())));
          }
          break;
        }
        case cilium::NetworkPolicyResource::kPolicy:
          IS_ENVOY_BUG("Selector-only delta Network Policy update unexpectedly included a policy");
          break;
        case cilium::NetworkPolicyResource::RESOURCE_NOT_SET:
          throw EnvoyException("Network Policy delta resource has no payload");
        }
      }
    } catch (const EnvoyException& e) {
      ENVOY_LOG(warn, "NetworkPolicy delta update for version {} failed: {}", system_version_info,
                e.what());
      stats_.updates_rejected_.inc();
      scheduleSelectorDeferredDeletion(selector_map_.revert());
      throw; // re-throw
    }

    // Same-stream selector-only updates become visible to existing policies by first publishing the
    // selector version itself and only then publishing that version number through the shared
    // stream state. Reversing this order would let workers observe a selector version that has not
    // yet been published in the selector map.
    auto new_version = selector_map_.publishNextVersion();
    if (new_version > 0) {
      policy_stream_state_->publishVersion(new_version);
      scheduleSelectorGCAndDeferredDeletion(new_version);
    }
    std::move(pending_resource_map).applyTo(resource_map_);
    return absl::OkStatus();
  }

  std::string version_name = fmt::format("NetworkPolicyMap version {}", system_version_info);
  Init::ManagerImpl version_init_manager(version_name);
  transport_factory_context_->setInitManager(version_init_manager);

  const auto* old_policy_map = load();
  PolicyMapSnapshot new_policy_map = is_new_stream ? PolicyMapSnapshot{} : *old_policy_map;
  ResourceMapOverlay pending_resource_map =
      is_new_stream ? ResourceMapOverlay() : ResourceMapOverlay(resource_map_);
  const auto policy_stream_state =
      is_new_stream
          ? std::make_shared<PolicyStreamState>(stream_generation, selector_map_.getVersion())
          : policy_stream_state_;
  try {
    const auto selector_update_version = selector_map_.prepareNextVersion();

    for (const auto& removed_resource : removed_resources) {
      ENVOY_LOG(trace, "Cilium removing network policy resource {}", removed_resource);
      const auto* resource_entry = pending_resource_map.findEntry(removed_resource);
      if (resource_entry == nullptr) {
        continue;
      }
      if (resource_entry->selectorResourceEntry()) {
        selector_map_.clear(removed_resource);
        pending_resource_map.erase(removed_resource);
        continue;
      }
      if (pending_resource_map.erasePolicyResourceIfPresent(new_policy_map, removed_resource)) {
        continue;
      }
      throw EnvoyException(
          fmt::format("Network Policy delta removed resource '{}' is a policy endpoint IP alias, "
                      "not a resource name",
                      removed_resource));
    }

    for (const auto& resource : added_resources) {
      const auto& typed_resource =
          dynamic_cast<const cilium::NetworkPolicyResource&>(resource.get().resource());
      const std::string& resource_name = resource.get().name();
      const auto* resource_entry = pending_resource_map.findEntry(resource_name);
      if (resource_entry == nullptr) {
        continue;
      }

      switch (typed_resource.resource_case()) {
      case cilium::NetworkPolicyResource::kSelector:
        pending_resource_map.eraseSelectorResourceIfPresent(resource_name);
        break;
      case cilium::NetworkPolicyResource::kPolicy:
        pending_resource_map.erasePolicyResourceIfPresent(new_policy_map, resource_name);
        break;
      case cilium::NetworkPolicyResource::RESOURCE_NOT_SET:
        break;
      }
    }

    for (const auto& resource : added_resources) {
      const auto& typed_resource =
          dynamic_cast<const cilium::NetworkPolicyResource&>(resource.get().resource());
      const std::string& resource_name = resource.get().name();

      if (typed_resource.resource_case() != cilium::NetworkPolicyResource::kSelector) {
        continue;
      }

      ENVOY_LOG(debug,
                "Received delta Network Policy selector resource {} in onConfigUpdate() "
                "version {}",
                resource_name, system_version_info);
      auto selector_handle =
          createOrReuseSelector(resource_name, typed_resource.selector(), selector_update_version);
      if (!pending_resource_map.emplace(resource_name,
                                        ResourceKey::selectorResource(selector_handle))) {
        throw EnvoyException(fmt::format(
            "Network Policy delta update for version {} has duplicate resource key '{}' on {} "
            "stream: "
            "incoming selector resource '{}' collides with existing {}",
            system_version_info, resource_name, is_new_stream ? "a new" : "an old", resource_name,
            pending_resource_map.describeExistingResourceKey(resource_name, new_policy_map)));
      }
    }

    for (const auto& resource : added_resources) {
      const auto& typed_resource =
          dynamic_cast<const cilium::NetworkPolicyResource&>(resource.get().resource());
      const std::string& resource_name = resource.get().name();

      switch (typed_resource.resource_case()) {
      case cilium::NetworkPolicyResource::kSelector:
        break;
      case cilium::NetworkPolicyResource::kPolicy: {
        const auto& config = typed_resource.policy();
        if (config.endpoint_ips().empty()) {
          throw EnvoyException("Network Policy has no endpoint ips");
        }
        if (config.endpoint_id() == 0) {
          throw EnvoyException("Network Policy endpoint_id must be non-zero");
        }
        ENVOY_LOG(debug,
                  "Received delta Network Policy resource {} for endpoint {}, endpoint_ip {} in "
                  "onConfigUpdate() version {}",
                  resource_name, config.endpoint_id(), config.endpoint_ips()[0],
                  system_version_info);

        auto policy = createOrReusePolicy(resource_name, config, policy_stream_state, resource_map_,
                                          &pending_resource_map);
        if (!pending_resource_map.emplace(resource_name, ResourceKey::policyResource(policy))) {
          throw EnvoyException(fmt::format(
              "Network Policy delta update for version {} has duplicate resource key '{}' on {} "
              "stream: "
              "incoming {} collides with existing {}",
              system_version_info, resource_name, is_new_stream ? "a new" : "an old",
              describePolicyResourceForLog(resource_name, config),
              pending_resource_map.describeExistingResourceKey(resource_name, new_policy_map)));
        }
        for (const auto& endpoint_ip : config.endpoint_ips()) {
          ENVOY_LOG(trace, "Cilium updating network policy for endpoint {}", endpoint_ip);
          if (!pending_resource_map.emplace(endpoint_ip, ResourceKey::policyEndpointIp())) {
            throw EnvoyException(fmt::format(
                "Network Policy delta update for version {} has duplicate resource key '{}' on {} "
                "stream: "
                "incoming {} collides with existing {}",
                system_version_info, endpoint_ip, is_new_stream ? "a new" : "an old",
                describePolicyResourceForLog(resource_name, config),
                pending_resource_map.describeExistingResourceKey(endpoint_ip, new_policy_map)));
          }
          if (!new_policy_map.emplace(endpoint_ip, policy).second) {
            throw EnvoyException(fmt::format(
                "Network Policy delta update for version {} has duplicate resource key '{}' on {} "
                "stream: "
                "incoming {} collides with existing {}",
                system_version_info, endpoint_ip, is_new_stream ? "a new" : "an old",
                describePolicyResourceForLog(resource_name, config),
                pending_resource_map.describeExistingResourceKey(endpoint_ip, new_policy_map)));
          }
        }
        break;
      }
      case cilium::NetworkPolicyResource::RESOURCE_NOT_SET:
        throw EnvoyException("Network Policy delta resource has no payload");
      }
    }
  } catch (const EnvoyException& e) {
    ENVOY_LOG(warn, "NetworkPolicy delta update for version {} failed: {}", system_version_info,
              e.what());
    stats_.updates_rejected_.inc();
    removeInitManager();
    scheduleSelectorDeferredDeletion(selector_map_.revert());
    throw; // re-throw
  }
  removeInitManager();
  installNewPolicyMap(std::move(new_policy_map), version_init_manager, std::move(version_name),
                      policy_stream_state);
  // do not carry over any resources from an old stream
  if (is_new_stream) {
    resource_map_.clear();
  }
  std::move(pending_resource_map).applyTo(resource_map_);

  return absl::OkStatus();
}

void NetworkPolicyMapImpl::onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason,
                                                const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
  ENVOY_LOG(debug, "Network Policy Update failed, keeping existing policy.");
}

ProtobufTypes::MessagePtr
NetworkPolicyMapImpl::dumpNetworkPolicyConfigs(const Matchers::StringMatcher& name_matcher) {
  ENVOY_LOG(debug, "Writing NetworkPolicies to NetworkPoliciesConfigDump");

  std::vector<uint64_t> policy_endpoint_ids;
  auto config_dump = std::make_unique<cilium::NetworkPoliciesConfigDump>();
  for (const auto& item : *load()) {
    // filter duplicates (policies are stored per endpoint ip)
    if (std::find(policy_endpoint_ids.begin(), policy_endpoint_ids.end(),
                  item.second->policy_proto_.endpoint_id()) != policy_endpoint_ids.end()) {
      continue;
    }

    if (!name_matcher.match(item.first)) {
      continue;
    }

    config_dump->mutable_networkpolicies()->Add()->CopyFrom(item.second->policy_proto_);
    policy_endpoint_ids.emplace_back(item.second->policy_proto_.endpoint_id());
  }

  return config_dump;
}

// Allow-all Egress policy
class AllowAllEgressPolicyInstanceImpl : public PolicyInstance {
public:
  AllowAllEgressPolicyInstanceImpl() {
    empty_map_.emplace(std::make_pair(uint16_t(1), uint16_t(1)), PortNetworkPolicyRules{});
  }

  bool allowed(bool ingress, uint16_t, uint32_t, uint16_t, Envoy::Http::RequestHeaderMap&,
               Cilium::AccessLog::Entry&) const override {
    return ingress ? false : true;
  }

  bool allowed(bool ingress, uint16_t, uint32_t, absl::string_view, uint16_t) const override {
    return ingress ? false : true;
  }

  const PortPolicy findPortPolicy(bool ingress, uint16_t) const override {
    return ingress ? PortPolicy(empty_map_, 0, versionMin) : PortPolicy(empty_map_, 1, versionMin);
  }

  bool useProxylib(bool, uint16_t, uint32_t, uint16_t, std::string&) const override {
    return false;
  }

  uint32_t getEndpointID() const override { return 0; }

  const IpAddressPair& getEndpointIPs() const override { return empty_ips; }

  std::string string() const override { return "AllowAllEgressPolicyInstanceImpl"; }

  void tlsWrapperMissingPolicyInc() const override {}

private:
  PolicySnapshot empty_map_;
  static const std::string empty_string;
  static const IpAddressPair empty_ips;
};
const std::string AllowAllEgressPolicyInstanceImpl::empty_string = "";
const IpAddressPair AllowAllEgressPolicyInstanceImpl::empty_ips{};

PolicyInstance& NetworkPolicyMap::getAllowAllEgressPolicy() {
  static AllowAllEgressPolicyInstanceImpl allow_all_egress_policy;
  return allow_all_egress_policy;
}

// Deny-all policy
class DenyAllPolicyInstanceImpl : public PolicyInstance {
public:
  DenyAllPolicyInstanceImpl() = default;

  bool allowed(bool, uint16_t, uint32_t, uint16_t, Envoy::Http::RequestHeaderMap&,
               Cilium::AccessLog::Entry&) const override {
    return false;
  }

  bool allowed(bool, uint16_t, uint32_t, absl::string_view, uint16_t) const override {
    return false;
  }

  const PortPolicy findPortPolicy(bool, uint16_t) const override {
    return PortPolicy(empty_map_, 0, versionMin);
  }

  bool useProxylib(bool, uint16_t, uint32_t, uint16_t, std::string&) const override {
    return false;
  }

  uint32_t getEndpointID() const override { return 0; }

  const IpAddressPair& getEndpointIPs() const override { return empty_ips; }

  std::string string() const override { return "DenyAllPolicyInstanceImpl"; }

  void tlsWrapperMissingPolicyInc() const override {}

private:
  PolicySnapshot empty_map_;
  static const std::string empty_string;
  static const IpAddressPair empty_ips;
};
const std::string DenyAllPolicyInstanceImpl::empty_string = "";
const IpAddressPair DenyAllPolicyInstanceImpl::empty_ips{};

PolicyInstance& NetworkPolicyMap::getDenyAllPolicy() {
  static DenyAllPolicyInstanceImpl deny_all_policy;
  return deny_all_policy;
}

const PolicyInstance*
NetworkPolicyMapImpl::getPolicyInstanceImpl(const std::string& endpoint_ip) const {
  const auto* map = load();
  auto it = map->find(endpoint_ip);
  if (it != map->end()) {
    return it->second.get();
  }
  return nullptr;
}

PolicyInstanceConstSharedPtr
NetworkPolicyMapImpl::getPolicyInstanceSharedImpl(const std::string& endpoint_ip) const {
  const auto* map = load();
  auto it = map->find(endpoint_ip);
  if (it != map->end()) {
    return it->second;
  }
  return nullptr;
}

uint64_t NetworkPolicyMapImpl::policySelectorStreamGenerationForTestImpl(
    const PolicyInstance& policy) const {
  if (const auto* policy_impl = dynamic_cast<const PolicyInstanceImpl*>(&policy)) {
    return policy_impl->policy_stream_state_->streamGeneration();
  }
  return 0;
}

SelectorVersion
NetworkPolicyMapImpl::policySelectorVersionForTestImpl(const PolicyInstance& policy) const {
  if (const auto* policy_impl = dynamic_cast<const PolicyInstanceImpl*>(&policy)) {
    return policy_impl->policy_stream_state_->version();
  }
  return versionMin;
}

// getPolicyInstance return a const reference to a policy in the policy map for the given
// 'endpoint_ip'. If there is no policy for the given IP, a default policy is returned,
// controlled by the 'default_allow_egress' argument as follows:
//
// 'false' - a deny all policy is returned,
// 'true' -  a deny all ingress / allow all egress is returned.
//
// Returning a default deny policy makes the caller report a "policy deny" rather than "internal
// server error" if no policy is found. This mirrors what bpf datapath does if no policy entry is
// found in the bpf policy map. The default deny for ingress with default allow for egress is needed
// for Cilium Ingress when there is no egress policy enforcement for the Ingress traffic.
const PolicyInstance& NetworkPolicyMap::getPolicyInstance(const std::string& endpoint_ip,
                                                          bool default_allow_egress) const {
  const auto* policy = impl_->getPolicyInstanceImpl(endpoint_ip);
  return policy ? *policy : default_allow_egress ? getAllowAllEgressPolicy() : getDenyAllPolicy();
}

} // namespace Cilium
} // namespace Envoy
