#pragma once

// NOLINT(namespace-envoy)

#include <atomic>
#include <cstdint>
#include <limits>
#include <memory>
#include <type_traits>
#include <utility>

#include "source/common/common/assert.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"

constexpr uint64_t versionMin = 0;
constexpr uint64_t versionMax = std::numeric_limits<uint64_t>::max() - 1;
constexpr uint64_t versionNotRemoved = std::numeric_limits<uint64_t>::max();

// Versioned.h provides a lock-free reader / single-writer versioned-value container,
// based on earlier implementations in OVS (C) and Cilium (Go).
//
// API contract and intended use:
//
// 1. Object model
//    - T is a CRTP node type inheriting from VersionedNode<T>.
//    - VersionedValue<T, R> stores a linked list of historical T nodes, newest first.
//    - VersionedReadable<T> exposes only the worker-safe read API: get(version).
//    - VersionedHandle<T, V> is a shared_ptr<const typename V::Readable>, so handles intentionally
//      expose only the readable API to worker/runtime code. Main-thread mutation goes through
//      VersionedMap, which keeps mutable shared_ptr<V> internally.
//    - The optional readable base R allows a handle to expose extra read-only metadata (for
//      example selector names) without exposing VersionedValue mutators.
//
// 2. Threading model
//    - There is exactly one mutator thread: the main thread.
//    - Worker threads may concurrently call VersionedReadable::get(version) and may traverse nodes
//      reached from a handle without additional locking.
//    - Any future cross-thread mutation must still preserve the exclusive-writer rule, e.g. by
//      holding an exclusive lock around all mutation.
//    - VersionedMap itself is main-thread-only. Its name directory (map_), dirty set, and
//      transactional state must not be accessed from worker threads.
//
// 3. VersionedMap transaction flow
//    - prepareNextVersion() starts a new unpublished update and returns the candidate version to
//      use for any main-thread lookups against in-flight state.
//    - insert(key, value) reuses the existing stable handle if the key is still present in the
//      main-thread directory; otherwise it creates a fresh handle.
//    - clear(key) marks the key's current value invisible in the candidate version but does not
//      erase the key from the main-thread directory immediately.
//    - publishNextVersion() publishes all pending changes, removes keys whose handle has no visible
//      value in the published version, and returns the new published version, or 0 if there was
//      nothing to publish.
//    - revert() discards the unpublished update, restores visibility of older nodes as needed, and
//      removes keys whose handle has no value in the published version.
//    - find(key) returns the stable readable handle parked under the key in the main-thread
//      directory. It does not itself answer whether the key is visible in any specific version; use
//      handle->get(version) for that.
//
// 4. Stable-handle semantics
//    - Updating an active key writes a new version onto the same stable handle.
//    - clear() followed by re-add of the same key in the same unpublished update also reuses that
//      same handle; the caller should compare against the candidate version returned from
//      prepareNextVersion(), not against the currently published version.
//    - Once a key has been fully removed across a published version boundary, the name disappears
//      from VersionedMap. A later same-name add creates a fresh stable handle.
//    - This is why old published policies can keep using an old cleared handle while refreshed
//      policies bind a new one after a later same-name re-add.
//
// 5. Reader semantics
//    - get(version) walks from the current head and returns the first node visible in the requested
//      version.
//    - The walk stops at the first node that was added before the requested version but is no
//      longer visible there; all remaining nodes are older and therefore already invisible in that
//      version.
//    - Querying an older published version after newer publishes is logically stale and may produce
//      outdated results, but it must remain memory-safe.
//
// 6. Deferred deletion / grace periods
//    - Unpublished nodes removed by revert() were never visible to workers, but are still unlinked
//      into a DeferredDeletion batch so that any concurrent traversal that had already stepped into
//      them cannot race with delete.
//    - gc(published_version) is only the first GC phase. It must be called only after all workers
//      have quiesced for that published version, unlinks nodes that are no longer visible to
//      anyone, and returns them in a DeferredDeletion batch.
//    - The returned DeferredDeletion batch must stay alive until all workers have quiesced once
//      more. Destroying the batch performs the actual node deletion.
//    - The production pattern is therefore: publish version N, wait for worker quiescence, call
//      gc(N), then keep the returned DeferredDeletion alive for one more quiescence round.
//
// 7. High-level memory-model rationale
//    - The main thread publishes new list links with 'release' stores to the list node pointers.
//    - Workers traverse with 'acquire' loads from the list node pointers, so they either observe
//      the old reachable chain or the newly published/unlinked chain, but not torn pointer state.
//    - published_version_ is stored with 'release' in publishNextVersion() and loaded with
//      'acquire' by readers, so readers that observe a new published version also observe the
//      prior main-thread mutations that made that version reachable.
//    - remove_version_ uses 'relaxed' atomic loads/stores because it controls logical visibility,
//      not structural reachability. Structural coherence and memory safety come from the
//      'release'/'acquire' ordering on list node pointers plus the extra deferred-deletion grace
//      period.
//    - Many mutation-side loads/stores are 'relaxed' because mutation is single-threaded on the
//      main thread.
//
// 8. DeferredDeletion implementation detail
//    - DeferredDeletion reuses VersionedNode::next_ to chain together unlinked nodes awaiting
//      destruction. This keeps deferred deletion self-contained without an extra node container.
//    - Public code must not rely on any semantics of detached invisible tails beyond memory safety;
//      only get(version) is the supported read API.
//
// 9. Test coverage in tests/versioned_test.cc
//    - Value-level tests cover visibility rules, shadowing, clear(), revert(), first-phase GC, and
//      deferred deletion ownership/move semantics.
//    - Map-level tests cover version numbering, publish-without-change, insert/update/clear/revert,
//      same-handle reuse for active updates and same-update clear+read, fresh-handle behavior
//      after published removal, and dirty-handle retention across multiple future GC runs.
//    - Stable validator tests verify consistent published snapshots and post-unlink/pre-deletion
//      states.
//    - A multithreaded chaos test exercises one writer with multiple busy-loop readers, repeated
//      publish/revert/GC cycles, stale-version reads, and traversal safety under deferred deletion.
//
template <typename T> class VersionedReadable;
template <typename T, typename R = VersionedReadable<T>> class VersionedValue;
template <typename T> class DeferredDeletion;
template <typename K, typename T, typename V = VersionedValue<T>> struct VersionedTestAccess;

// VersionedNode is CRTP type on T, T must inherit from VersionedNode<T>
template <typename T> class VersionedNode {
public:
  template <class... Args>
  VersionedNode()
      : next_(nullptr), add_version_(versionNotRemoved), remove_version_(versionNotRemoved) {}

private:
  template <typename U> friend class VersionedReadable;
  template <typename U, typename R> friend class VersionedValue;
  template <typename U> friend class DeferredDeletion;
  template <typename K, typename U, typename V> friend struct VersionedTestAccess;

  bool isUnpublished() const { return add_version_ == versionNotRemoved; }

  void setAddVersion(uint64_t version) {
    ASSERT(version < versionNotRemoved);
    add_version_ = version; // set before published
  }

  void removeInVersion(uint64_t version) {
    remove_version_.store(version, std::memory_order_relaxed);
  }

  bool isVisibleInVersion(uint64_t version) const {
    return add_version_ <= version && version < remove_version_.load(std::memory_order_relaxed);
  }

  bool isAddedAfterVersion(uint64_t version) const { return add_version_ > version; }

  bool isAddedBeforeVersion(uint64_t version) const { return add_version_ < version; }

  bool isEventuallyInvisible() const {
    return remove_version_.load(std::memory_order_relaxed) < versionNotRemoved;
  }

  bool isVisibleOnlyBeforeVersion(uint64_t version) const {
    return remove_version_.load(std::memory_order_relaxed) <= version;
  }

  bool isRemovedAfterVersion(uint64_t version) const {
    const auto remove_version = remove_version_.load(std::memory_order_relaxed);
    return remove_version < versionNotRemoved && version < remove_version;
  }

  VersionedNode<T>* getNext() const { return next_.load(std::memory_order_acquire); }

  void setNext(VersionedNode<T>* next) { return next_.store(next, std::memory_order_release); }

  VersionedNode<T>* getNextProtected() const { return next_.load(std::memory_order_relaxed); }
  std::atomic<VersionedNode<T>*>* getNextP() { return &next_; }

  T* value() { return static_cast<T*>(this); }
  const T* value() const { return static_cast<const T*>(this); }

  std::atomic<VersionedNode<T>*> next_;

  uint64_t add_version_;                 // Version object was added in.
  std::atomic<uint64_t> remove_version_; // Version object is removed in.
};

template <typename T> class VersionedReadable {
public:
  const T* get(uint64_t version) const {
    for (auto node = head_.load(std::memory_order_acquire); node; node = node->getNext()) {
      if (node->isVisibleInVersion(version)) {
        return node->value();
      }
      // stop traveral on first non-visible version that was added before this version, all
      // remaining nodes are already invisible.
      if (node->isAddedBeforeVersion(version)) {
        break;
      }
    }
    return nullptr; // not found
  }

protected:
  VersionedReadable() : head_(nullptr) {}

  template <typename U, typename R> friend class VersionedValue;
  template <typename U> friend class DeferredDeletion;
  template <typename K, typename U, typename V> friend struct VersionedTestAccess;

  std::atomic<VersionedNode<T>*> head_;
};

// T is the CRTP node type stored in the version chain. R is the read-only interface exposed
// through VersionedHandle: it defaults to VersionedReadable<T>, but callers may provide a richer
// readable base when handles need extra read-side API without exposing the main-thread mutators.
template <typename T, typename R> class VersionedValue : public R {
public:
  using Readable = R;
  using R::head_;

  VersionedValue() = default;

  template <class... Args, typename = std::enable_if_t<std::is_constructible_v<R, Args...>>>
  explicit VersionedValue(Args&&... args) : R(std::forward<Args>(args)...) {}

  ~VersionedValue() {
    VersionedNode<T>* next;
    for (auto node = head_.load(std::memory_order_relaxed); node; node = next) {
      next = node->getNextProtected();
      delete node->value();
    }
  }

  // make all versions invisible starting at "version"
  void clear(uint64_t version) {
    for (auto node = head_.load(std::memory_order_relaxed); node; node = node->getNextProtected()) {
      if (!node->isEventuallyInvisible()) {
        node->removeInVersion(version);
      }
    }
  }

  void set(uint64_t version, VersionedNode<T>* node) {
    // publish a new version that is visible starting at "version"
    ASSERT(node->isUnpublished()); // node not pushed into a list yet
    node->setAddVersion(version);
    node->setNext(head_.load(std::memory_order_relaxed));
    head_.store(node, std::memory_order_release);

    // make all other versions invisible at "version", starting from the first old node.
    for (node = node->getNextProtected(); node; node = node->getNextProtected()) {
      if (node->isVisibleInVersion(version)) {
        node->removeInVersion(version);
      }
    }
  }

  bool empty() const { return head_.load(std::memory_order_relaxed) == nullptr; }

  // Unlink unpublished versions added after 'version' and append them to 'deferred' for deletion
  // after an additional grace period. Removed nodes that were still visible in 'version' are
  // restored.
  void revert(uint64_t version, DeferredDeletion<T>& deferred) {
    auto prev = &head_;
    VersionedNode<T>* next;
    for (auto node = head_.load(std::memory_order_relaxed); node; node = next) {
      next = node->getNextProtected();
      if (node->isAddedAfterVersion(version)) {
        // unlink node by pointing prev to next
        prev->store(next, std::memory_order_release);
        deferred.push(node);
        // prev stays
        continue;
      }
      if (node->isRemovedAfterVersion(version)) {
        // visibility was limited, restore
        node->removeInVersion(versionNotRemoved);
      }
      prev = node->getNextP();
    }
  }

  // Unlink all versions not visible to anyone after the "version" was published and all readers
  // have quiesced, but do not delete them yet. Unlinked nodes are appended to 'deferred' and are
  // only deleted after one more worker-thread quiescence round. Any nodes not yet visible at
  // "version" must not be unlinked.
  // Returns true if there are no future version removals left in this handle after this first
  // phase GC run.
  bool gcForVersion(uint64_t version, DeferredDeletion<T>& deferred) {
    ASSERT(version < versionNotRemoved);
    auto prev = &head_;
    VersionedNode<T>* next;
    bool has_future_gc_work = false;
    for (auto node = head_.load(std::memory_order_relaxed); node; node = next) {
      next = node->getNextProtected();
      if (node->isVisibleOnlyBeforeVersion(version)) {
        // unlink node by pointing prev to next
        prev->store(next, std::memory_order_release);
        deferred.push(node);
        // prev stays
        continue;
      }
      if (node->isEventuallyInvisible()) {
        has_future_gc_work = true;
      }
      prev = node->getNextP();
    }
    return !has_future_gc_work;
  }

protected:
  friend class DeferredDeletion<T>;
  template <typename K, typename U, typename V> friend struct VersionedTestAccess;
};

template <typename T> class DeferredDeletion : protected VersionedValue<T> {
public:
  // Bring `head_` from the templated base class into this scope so the rest of the code can use
  // normal unqualified member access. Without this, dependent-base lookup would require
  // `this->head_` everywhere.
  using VersionedValue<T>::head_;

  DeferredDeletion() = default;
  DeferredDeletion(const DeferredDeletion&) = delete;
  DeferredDeletion& operator=(const DeferredDeletion&) = delete;
  DeferredDeletion(DeferredDeletion&& other) noexcept {
    head_.store(other.head_.exchange(nullptr, std::memory_order_relaxed),
                std::memory_order_relaxed);
    tail_ = std::exchange(other.tail_, nullptr);
  }
  DeferredDeletion& operator=(DeferredDeletion&&) noexcept = delete;
  ~DeferredDeletion() = default;

  bool empty() const { return head_.load(std::memory_order_relaxed) == nullptr; }

private:
  template <typename U, typename R> friend class VersionedValue;

  void push(VersionedNode<T>* node) {
    node->setNext(nullptr);
    if (tail_) {
      tail_->setNext(node);
    } else {
      // Only the main thread is accessing the deferred-deletion head, hence relaxed.
      head_.store(node, std::memory_order_relaxed);
    }
    tail_ = node;
  }

  VersionedNode<T>* tail_{nullptr};
};

template <typename T, typename V = VersionedValue<T>>
using VersionedHandle = std::shared_ptr<const typename V::Readable>;

// VersionedMap is main-thread / exclusive-writer only: map_, pending_keys_, dirty_values_, and
// all mutation methods are accessed only by the single publishing thread. Worker threads only use
// the published Handle objects and then call the read-only handle API.
template <typename K, typename T, typename V = VersionedValue<T>> class VersionedMap {
public:
  static_assert(std::is_base_of_v<typename V::Readable, V>);
  static_assert(std::is_base_of_v<VersionedReadable<T>, typename V::Readable>);
  using Handle = VersionedHandle<T, V>;

  uint64_t getVersion() const { return published_version_.load(std::memory_order_acquire); }

  Handle find(const K& key) const {
    auto it = map_.find(key);
    if (it != map_.cend()) {
      return it->second;
    }
    return nullptr;
  }

  uint64_t prepareNextVersion() {
    ASSERT(pending_keys_.empty());
    return ++next_version_;
  }

  Handle insert(const K& key, T* value) {
    ASSERT(next_version_ > published_version_.load(std::memory_order_relaxed));
    auto [it, inserted] = map_.try_emplace(key);
    if (inserted) {
      if constexpr (std::is_constructible_v<V, const K&>) {
        it->second = std::make_shared<V>(key);
      } else {
        it->second = std::make_shared<V>();
      }
    }
    auto& handle = it->second;
    handle->set(next_version_, value);
    pending_keys_.emplace(key);
    return handle;
  }

  void clear(const K& key) {
    ASSERT(next_version_ > published_version_.load(std::memory_order_relaxed));
    auto it = map_.find(key);
    if (it != map_.cend()) {
      it->second->clear(next_version_);
      pending_keys_.emplace(key);
    }
  }

  // returns the newly published version, or 0 if there was nothing to publish
  uint64_t publishNextVersion() {
    auto version = published_version_.load(std::memory_order_relaxed);
    if (next_version_ <= version || pending_keys_.empty()) {
      // no changes, revert back to the published version
      next_version_ = version;
      pending_keys_.clear();
      return 0;
    }
    for (const auto& key : pending_keys_) {
      auto it = map_.find(key);
      ASSERT(it != map_.end());
      dirty_values_.emplace(it->second);
      if (it->second->get(next_version_) == nullptr) {
        map_.erase(it);
      }
    }
    published_version_.store(next_version_, std::memory_order_release);
    pending_keys_.clear();
    return next_version_;
  }

  DeferredDeletion<T> revert() {
    auto version = published_version_.load(std::memory_order_relaxed);
    DeferredDeletion<T> deferred;
    for (const auto& key : pending_keys_) {
      auto it = map_.find(key);
      ASSERT(it != map_.end());
      it->second->revert(version, deferred);
      if (it->second->get(version) == nullptr) {
        map_.erase(it);
      }
    }
    pending_keys_.clear();
    next_version_ = version;
    return deferred;
  }

  // First phase GC after all readers have quiesced for 'published_version'. This unlinks nodes that
  // are no longer visible and returns them in a deferred-deletion batch that must survive until all
  // readers have quiesced once more before it is destroyed.
  DeferredDeletion<T> gc(uint64_t published_version) {
    DeferredDeletion<T> deferred;
    for (auto it = dirty_values_.begin(); it != dirty_values_.end();) {
      const auto& handle = *it;
      if (handle->gcForVersion(published_version, deferred)) {
        dirty_values_.erase(it++);
        continue;
      }
      ++it;
    }
    return deferred;
  }

private:
  friend struct VersionedTestAccess<K, T, V>;
  using MutableHandle = std::shared_ptr<V>;

  // Persistent published state.
  std::atomic<uint64_t> published_version_{versionMin};
  absl::flat_hash_map<K, MutableHandle> map_;
  absl::flat_hash_set<MutableHandle> dirty_values_;

  // Transactional state for the currently prepared unpublished update.
  // Valid only after prepareNextVersion() and until publishNextVersion() or revert().
  // `next_version_` is the candidate version being built, and `pending_keys_`
  // contains the keys touched in that candidate update. The container is reused
  // across updates to avoid repeated allocation churn.
  uint64_t next_version_{versionMin};
  absl::flat_hash_set<K> pending_keys_;
};

template <typename K, typename T, typename V> struct VersionedTestAccess {
  using Map = VersionedMap<K, T, V>;
  using Handle = typename Map::Handle;
  using MutableHandle = typename Map::MutableHandle;
  using Node = VersionedNode<T>;

  static const absl::flat_hash_map<K, MutableHandle>& entries(const Map& map) { return map.map_; }

  static const absl::flat_hash_set<MutableHandle>& dirtyValues(const Map& map) {
    return map.dirty_values_;
  }

  static const Node* head(const Handle& handle) {
    if (handle == nullptr) {
      return nullptr;
    }
    auto value = std::static_pointer_cast<const V>(handle);
    return value->head_.load(std::memory_order_acquire);
  }

  static const Node* next(const Node* node) {
    return node ? node->next_.load(std::memory_order_acquire) : nullptr;
  }

  static const T* value(const Node* node) { return node ? node->value() : nullptr; }

  static uint64_t addVersion(const Node* node) { return node->add_version_; }

  static uint64_t removeVersion(const Node* node) {
    return node->remove_version_.load(std::memory_order_relaxed);
  }

  static bool isVisibleInVersion(const Node* node, uint64_t version) {
    return node && node->isVisibleInVersion(version);
  }

  static bool isAddedAfterVersion(const Node* node, uint64_t version) {
    return node && node->isAddedAfterVersion(version);
  }
};
