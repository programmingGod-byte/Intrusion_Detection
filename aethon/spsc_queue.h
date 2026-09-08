#pragma once

#include "aethon/aethon.h"
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>
#include <sys/types.h>
#include <type_traits>
#include <utility>

namespace aethon {
namespace detail {

template <class T> struct ProducerConsumerQueue {
  using value_type = T;

  ProducerConsumerQueue(const ProducerConsumerQueue &) = delete;
  ProducerConsumerQueue &operator=(const ProducerConsumerQueue &) = delete;

  explicit ProducerConsumerQueue(u_int32_t size)
      : size_(size), mask_(size - 1),
        records(static_cast<T *>(std::malloc(sizeof(T) * size))), readIndex_(0),
        writeIndex_(0) {
    AETHON_SAFE_CHECK(size >= 2 && (size & (size - 1)) == 0,
                      "size must be a power of 2");
    if (!records) {
      throw std::bad_alloc();
    }
  }

  ~ProducerConsumerQueue() {
    if (!std::is_trivially_destructible<T>::value) {
      size_t readIndex = readIndex_;
      size_t endIndex = writeIndex_;

      while (readIndex != endIndex) {
        records[readIndex].~T();
        readIndex = (readIndex + 1) & mask_;
      }
    }

    std::free(records);
  }

  template <typename... Args>
  AETHON_ALWAYS_INLINE bool write(Args &&...recordArgs) {
    auto const currentWrite = writeIndex_.load(std::memory_order_relaxed);
    auto nextRecord = (currentWrite + 1) & mask_;

    AETHON_BUILTIN_PREFETCH(&records[nextRecord], 1, 3);

    if (AETHON_LIKELY(nextRecord !=
                      readIndex_.load(std::memory_order_acquire))) {
      new (&records[currentWrite]) T(std::forward<Args>(recordArgs)...);
      writeIndex_.store(nextRecord, std::memory_order_release);
      return true;
    }
    return false;
  }

  AETHON_ALWAYS_INLINE bool read(T &record) {
    auto const currentRead = readIndex_.load(std::memory_order_relaxed);

    if (AETHON_UNLIKELY(currentRead ==
                        writeIndex_.load(std::memory_order_acquire))) {
      return false;
    }

    auto nextRecord = (currentRead + 1) & mask_;

    AETHON_BUILTIN_PREFETCH(&records[nextRecord], 0, 3);

    record = std::move(records[currentRead]);
    records[currentRead].~T();

    readIndex_.store(nextRecord, std::memory_order_release);

    return true;
  }

  size_t capacity() const { return size_ - 1; }

  bool isEmpty() const {
    return readIndex_.load(std::memory_order_acquire) ==
           writeIndex_.load(std::memory_order_acquire);
  }

  bool isFull() const {
    auto nextRecord = (writeIndex_.load(std::memory_order_acquire) + 1) & mask_;
    return nextRecord == readIndex_.load(std::memory_order_acquire);
  }

private:
  using AtomicIndex = std::atomic<unsigned int>;
  char pad0_[implementation::hardware_destructive_interference_size];
  const u_int32_t size_;
  const u_int32_t mask_;

  T *const records;

  alignas(implementation::hardware_destructive_interference_size)
      AtomicIndex readIndex_;
  alignas(implementation::hardware_destructive_interference_size)
      AtomicIndex writeIndex_;

  char pad1_[implementation::hardware_destructive_interference_size -
             sizeof(AtomicIndex)];
};
} // namespace detail
} // namespace aethon
