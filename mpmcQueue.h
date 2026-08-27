#pragma once

#include "aethon.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <stdexcept>x
#include <utility>

namespace aethon {

namespace detail {

template <typename T> struct SingleElementQueue {
  alignas(alignof(T)) char contents_[sizeof(T)];
  std::atomic<uint32_t> turn_{0};
};

} // namespace detail

template <typename T> class MpmcQueue {
public:
  explicit MpmcQueue(size_t capacity)
      : capacity_(capacity), mask_(capacity - 1),
        shift_(__builtin_ctz(capacity)), pushTicket_(0), popTicket_(0) {
    if (capacity < 2 || (capacity & (capacity - 1)) != 0) {
      throw std::invalid_argument("Capacity must be a power of 2!");
    }
    slots_ = new detail::SingleElementQueue<T>[capacity_];
  }

  ~MpmcQueue() { delete[] slots_; }

  MpmcQueue(const MpmcQueue &) = delete;
  MpmcQueue &operator=(const MpmcQueue &) = delete;

  template <typename... Args> AETHON_ALWAYS_INLINE bool write(Args &&...args) {
    uint64_t ticket = pushTicket_.fetch_add(1, std::memory_order_relaxed);
    size_t idx = ticket & mask_;
    uint32_t expectedTurn = static_cast<uint32_t>(ticket >> shift_) << 1;

    AETHON_BUILTIN_PREFETCH(&slots_[(idx + 1) & mask_], 1, 3);

    while (slots_[idx].turn_.load(std::memory_order_acquire) != expectedTurn) {
      AETHON_PAUSE_CPU_INSTRUCTION;
    }

    new (slots_[idx].contents_) T(std::forward<Args>(args)...);
    slots_[idx].turn_.store(expectedTurn + 1, std::memory_order_release);
    return true;
  }

  template <typename... Args>
  AETHON_ALWAYS_INLINE void blockingWrite(Args &&...args) {
    uint64_t ticket = pushTicket_.fetch_add(1, std::memory_order_relaxed);
    size_t idx = ticket & mask_;
    uint32_t expectedTurn = static_cast<uint32_t>(ticket >> shift_) << 1;

    AETHON_BUILTIN_PREFETCH(&slots_[(idx + 1) & mask_], 1, 3);

    uint32_t spin_count = 0;
    while (true) {
      uint32_t currentTurn = slots_[idx].turn_.load(std::memory_order_acquire);
      if (AETHON_LIKELY(currentTurn == expectedTurn)) {
        break;
      }

      if (spin_count++ < 1000) {
        AETHON_PAUSE_CPU_INSTRUCTION;
      } else {
        implementation::futex_wait(&slots_[idx].turn_, currentTurn);
      }
    }

    new (slots_[idx].contents_) T(std::forward<Args>(args)...);
    slots_[idx].turn_.store(expectedTurn + 1, std::memory_order_release);
    implementation::futex_wake(&slots_[idx].turn_);
  }

  AETHON_ALWAYS_INLINE bool read(T &result) {
    uint64_t ticket = popTicket_.fetch_add(1, std::memory_order_relaxed);
    size_t idx = ticket & mask_;
    uint32_t expectedTurn =
        ((static_cast<uint32_t>(ticket >> shift_)) << 1) | 1;

    AETHON_BUILTIN_PREFETCH(&slots_[(idx + 1) & mask_], 0, 3);

    while (slots_[idx].turn_.load(std::memory_order_acquire) != expectedTurn) {
      AETHON_PAUSE_CPU_INSTRUCTION;
    }

    T *itemPtr = reinterpret_cast<T *>(slots_[idx].contents_);
    result = std::move(*itemPtr);
    itemPtr->~T();

    slots_[idx].turn_.store(expectedTurn + 1, std::memory_order_release);
    return true;
  }

  AETHON_ALWAYS_INLINE bool blockingRead(T &result) {
    uint64_t ticket = popTicket_.fetch_add(1, std::memory_order_relaxed);
    size_t idx = ticket & mask_;
    uint32_t expectedTurn =
        ((static_cast<uint32_t>(ticket >> shift_)) << 1) | 1;

    AETHON_BUILTIN_PREFETCH(&slots_[(idx + 1) & mask_], 0, 3);

    uint32_t spin_count = 0;
    while (true) {
      uint32_t currentTurn = slots_[idx].turn_.load(std::memory_order_acquire);
      if (AETHON_LIKELY(currentTurn == expectedTurn)) {
        break;
      }

      if (spin_count++ < 1000) {
        AETHON_PAUSE_CPU_INSTRUCTION;
      } else {
        implementation::futex_wait(&slots_[idx].turn_, currentTurn);
      }
    }

    T *itemPtr = reinterpret_cast<T *>(slots_[idx].contents_);
    result = std::move(*itemPtr);
    itemPtr->~T();

    slots_[idx].turn_.store(expectedTurn + 1, std::memory_order_release);
    implementation::futex_wake(&slots_[idx].turn_);
    return true;
  }

  size_t capacity() const noexcept { return capacity_; }

private:
  const size_t capacity_;
  const size_t mask_;
  const size_t shift_;
  detail::SingleElementQueue<T> *slots_;

  alignas(64) std::atomic<uint64_t> pushTicket_;
  alignas(64) std::atomic<uint64_t> popTicket_;
};

} // namespace aethon
