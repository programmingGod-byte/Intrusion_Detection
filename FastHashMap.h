#pragma once
#include "aethon.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace aethon {

template <typename T> struct DefaultHash {
  AETHON_ALWAYS_INLINE size_t operator()(T key) const noexcept {
    uint64_t x = static_cast<uint64_t>(key);
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return static_cast<size_t>(x);
  }
};

template <> struct DefaultHash<std::string> {
  AETHON_ALWAYS_INLINE size_t
  operator()(const std::string &key) const noexcept {
    uint64_t hash = 14695981039346656037ULL;
    for (char c : key) {
      hash ^= static_cast<uint64_t>(c);
      hash *= 1099511628211ULL;
    }
    return static_cast<size_t>(hash);
  }
};

template <typename Key, typename Value, Key EmptyKey = Key{},
          Key TombstoneKey = static_cast<Key>(-1),
          typename Hash = DefaultHash<Key>>
class LockFreeHashMap {
public:
  struct Cell {
    std::atomic<Key> key{EmptyKey};
    Value val{};

    Cell() = default;
  };

private:
  Cell *cells_;
  size_t capacity_;
  size_t mask_;
  Hash hasher_{};
  std::atomic<size_t> size_{0};

  AETHON_ALWAYS_INLINE size_t hash_key(const Key &key) const noexcept {
    return hasher_(key);
  }

public:
  explicit LockFreeHashMap(size_t capacity = 1024) : size_(0) {
    AETHON_SAFE_CHECK((capacity & (capacity - 1)) == 0,
                      "LockFreeHashMap capacity must be a power of 2!");

    capacity_ = capacity;
    mask_ = capacity_ - 1;
    cells_ = new Cell[capacity_];
  }

  ~LockFreeHashMap() {
    if constexpr (!std::is_trivially_destructible<Value>::value) {
      for (size_t i = 0; i < capacity_; ++i) {
        Key k = cells_[i].key.load(std::memory_order_relaxed);
        if (k != EmptyKey && k != TombstoneKey) {
          cells_[i].val.~Value();
        }
      }
    }
    delete[] cells_;
  }

  LockFreeHashMap(const LockFreeHashMap &) = delete;
  LockFreeHashMap &operator=(const LockFreeHashMap &) = delete;

  template <typename... Args>
  AETHON_ALWAYS_INLINE bool emplace(const Key &key, Args &&...args) {
    AETHON_SAFE_CHECK(key != EmptyKey && key != TombstoneKey,
                      "Cannot insert sentinel key into LockFreeHashMap!");

    size_t idx = hash_key(key) & mask_;
    size_t probes = 0;

    while (AETHON_LIKELY(probes < capacity_)) {
      AETHON_BUILTIN_PREFETCH(&cells_[(idx + 1) & mask_], 1, 3);
      Key k = cells_[idx].key.load(std::memory_order_relaxed);

      if (k == EmptyKey || k == TombstoneKey) {
        Key expected = k;
        if (cells_[idx].key.compare_exchange_strong(
                expected, key, std::memory_order_release,
                std::memory_order_relaxed)) {
          cells_[idx].val = Value(std::forward<Args>(args)...);
          size_.fetch_add(1, std::memory_order_relaxed);
          return true;
        }
        k = expected;
      }

      if (k == key) {
        cells_[idx].val = Value(std::forward<Args>(args)...);
        return false;
      }

      idx = (idx + 1) & mask_;
      ++probes;
    }

    AETHON_SAFE_CHECK(Trait::always_false<int>, "LockFreeHashMap is full!");
    return false;
  }

  AETHON_ALWAYS_INLINE bool insert(const Key &key, const Value &val) {
    return emplace(key, val);
  }

  AETHON_ALWAYS_INLINE bool insert(const Key &key, Value &&val) {
    return emplace(key, std::move(val));
  }

  AETHON_ALWAYS_INLINE std::optional<Value>
  find(const Key &key) const noexcept {
    AETHON_SAFE_CHECK(key != EmptyKey && key != TombstoneKey,
                      "Cannot search for sentinel keys!");

    size_t idx = hash_key(key) & mask_;
    size_t probes = 0;

    while (AETHON_LIKELY(probes < capacity_)) {
      AETHON_BUILTIN_PREFETCH(&cells_[(idx + 1) & mask_], 0, 3);
      Key k = cells_[idx].key.load(std::memory_order_acquire);

      if (k == key) {
        return cells_[idx].val;
      }

      if (k == EmptyKey) {
        return std::nullopt;
      }

      idx = (idx + 1) & mask_;
      ++probes;
    }

    return std::nullopt;
  }

  AETHON_ALWAYS_INLINE bool get(const Key &key, Value &out_val) const noexcept {
    AETHON_SAFE_CHECK(key != EmptyKey && key != TombstoneKey,
                      "Cannot search for sentinel keys!");

    size_t idx = hash_key(key) & mask_;
    size_t probes = 0;

    while (AETHON_LIKELY(probes < capacity_)) {
      AETHON_BUILTIN_PREFETCH(&cells_[(idx + 1) & mask_], 0, 3);
      Key k = cells_[idx].key.load(std::memory_order_acquire);

      if (k == key) {
        out_val = cells_[idx].val;
        return true;
      }

      if (k == EmptyKey) {
        return false;
      }

      idx = (idx + 1) & mask_;
      ++probes;
    }

    return false;
  }

  AETHON_ALWAYS_INLINE bool contains(const Key &key) const noexcept {
    Value dummy{};
    return get(key, dummy);
  }

  AETHON_ALWAYS_INLINE bool erase(const Key &key) noexcept {
    AETHON_SAFE_CHECK(key != EmptyKey && key != TombstoneKey,
                      "Cannot erase sentinel keys!");

    size_t idx = hash_key(key) & mask_;
    size_t probes = 0;

    while (AETHON_LIKELY(probes < capacity_)) {
      AETHON_BUILTIN_PREFETCH(&cells_[(idx + 1) & mask_], 0, 3);
      Key k = cells_[idx].key.load(std::memory_order_relaxed);

      if (k == key) {
        Key expected = key;
        if (cells_[idx].key.compare_exchange_strong(
                expected, TombstoneKey, std::memory_order_release,
                std::memory_order_relaxed)) {
          if constexpr (!std::is_trivially_destructible<Value>::value) {
            cells_[idx].val.~Value();
          }
          size_.fetch_sub(1, std::memory_order_relaxed);
          return true;
        }
      }

      if (k == EmptyKey) {
        return false;
      }

      idx = (idx + 1) & mask_;
      ++probes;
    }

    return false;
  }

  AETHON_ALWAYS_INLINE size_t size() const noexcept {
    return size_.load(std::memory_order_relaxed);
  }

  AETHON_ALWAYS_INLINE size_t capacity() const noexcept { return capacity_; }

  AETHON_ALWAYS_INLINE bool empty() const noexcept { return size() == 0; }
};

} // namespace aethon