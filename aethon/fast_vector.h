#pragma once

#include "aethon/aethon.h"
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace aethon {
template <typename T, size_t InlineCapacity = 8> class SmallVector {
private:
  alignas(alignof(T)) char inlineBuffer_[sizeof(T) * InlineCapacity];
  size_t size_;
  size_t capacity_;
  T *data_;

  AETHON_ALWAYS_INLINE bool is_inline() const noexcept {
    return data_ == reinterpret_cast<const T *>(inlineBuffer_);
  }

  void reallocate(size_t new_capacity) {
    T *new_data = static_cast<T *>(std::malloc(sizeof(T) * new_capacity));
    if (AETHON_UNLIKELY(!new_data)) {
      AETHON_SAFE_CHECK(Trait::always_false<int>,
                        "cannot able to allocate data on malloc");
    }

    AETHON_BUILTIN_PREFETCH(new_data, 1, 3);
    AETHON_BUILTIN_PREFETCH(data_, 0, 3);

    if constexpr (std::is_trivially_copyable<T>::value) {
      std::memcpy(new_data, data_, sizeof(T) * size_);
    } else {
      for (size_t i = 0; i < size_; i++) {
        new (new_data + i) T(std::move(data_[i]));
        data_[i].~T();
      }
    }

    if (AETHON_UNLIKELY(!is_inline())) {
      std::free(data_);
    }

    data_ = new_data;
    capacity_ = new_capacity;
  }

  AETHON_ALWAYS_INLINE void grow() {
    size_t new_capacity = (capacity_ * 3 + 1) / 2;
    reallocate(new_capacity);
  }

public:
  using iterator = T *;
  using const_iterator = const T *;

  AETHON_ALWAYS_INLINE SmallVector() noexcept
      : size_(0), capacity_(InlineCapacity),
        data_(reinterpret_cast<T *>(inlineBuffer_)) {}

  SmallVector(SmallVector &&other) noexcept
      : size_(0), capacity_(InlineCapacity),
        data_(reinterpret_cast<T *>(inlineBuffer_)) {
    if (AETHON_LIKELY(other.is_inline())) {
      if constexpr (std::is_trivially_copyable<T>::value) {
        std::memcpy(data_, other.data_, sizeof(T) * other.size_);
      } else {
        for (size_t i = 0; i < other.size_; i++) {
          new (data_ + i) T(std::move(other.data_[i]));
          other.data_[i].~T();
        }
      }
      size_ = other.size_;
      other.size_ = 0;
    } else {
      data_ = other.data_;
      capacity_ = other.capacity_;
      size_ = other.size_;

      other.data_ = reinterpret_cast<T *>(other.inlineBuffer_);
      other.capacity_ = InlineCapacity;
      other.size_ = 0;
    }
  }

  SmallVector(const SmallVector &other)
      : size_(0), capacity_(InlineCapacity),
        data_(reinterpret_cast<T *>(inlineBuffer_)) {
    reserve(other.size_);
    if constexpr (std::is_trivially_copyable<T>::value) {
      std::memcpy(data_, other.data_, sizeof(T) * other.size_);
      size_ = other.size_;
    } else {
      for (size_t i = 0; i < other.size_; ++i) {
        push_back(other[i]);
      }
    }
  }

  SmallVector &operator=(SmallVector &&other) noexcept {
    if (AETHON_LIKELY(this != &other)) {
      clear();
      if (AETHON_UNLIKELY(!is_inline())) {
        std::free(data_);
      }
      if (AETHON_LIKELY(other.is_inline())) {
        data_ = reinterpret_cast<T *>(inlineBuffer_);
        capacity_ = InlineCapacity;
        if constexpr (std::is_trivially_copyable<T>::value) {
          std::memcpy(data_, other.data_, sizeof(T) * other.size_);
        } else {
          for (size_t i = 0; i < other.size_; ++i) {
            new (data_ + i) T(std::move(other.data_[i]));
            other.data_[i].~T();
          }
        }
        size_ = other.size_;
        other.size_ = 0;
      } else {
        data_ = other.data_;
        capacity_ = other.capacity_;
        size_ = other.size_;

        other.data_ = reinterpret_cast<T *>(other.inlineBuffer_);
        other.capacity_ = InlineCapacity;
        other.size_ = 0;
      }
    }
    return *this;
  }

  SmallVector &operator=(const SmallVector &other) {
    if (AETHON_LIKELY(this != &other)) {
      clear();
      reserve(other.size_);
      if constexpr (std::is_trivially_copyable<T>::value) {
        std::memcpy(data_, other.data_, sizeof(T) * other.size_);
        size_ = other.size_;
      } else {
        for (size_t i = 0; i < other.size_; ++i) {
          push_back(other[i]);
        }
      }
    }
    return *this;
  }

  AETHON_ALWAYS_INLINE void reserve(size_t new_capacity) {
    if (AETHON_UNLIKELY(new_capacity > capacity_)) {
      reallocate(new_capacity);
    }
  }

  template <typename... Args>
  AETHON_ALWAYS_INLINE T &emplace_back(Args &&...args) {
    if (AETHON_UNLIKELY(size_ == capacity_)) {
      grow();
    }
    T *slot = data_ + size_;
    AETHON_BUILTIN_PREFETCH(slot + 1, 1, 3);
    new (slot) T(std::forward<Args>(args)...);

    ++size_;
    return *slot;
  }

  AETHON_ALWAYS_INLINE void push_back(const T &value) { emplace_back(value); }

  AETHON_ALWAYS_INLINE void push_back(T &&value) {
    emplace_back(std::move(value));
  }

  AETHON_ALWAYS_INLINE void pop_back() {
    if (AETHON_LIKELY(size_ > 0)) {
      --size_;
      if constexpr (!std::is_trivially_destructible<T>::value) {
        data_[size_].~T();
      }
    }
  }

  void shrink_to_fit() {
    if (AETHON_UNLIKELY(!is_inline())) {
      if (size_ <= InlineCapacity) {
        T *inline_data = reinterpret_cast<T *>(inlineBuffer_);
        if constexpr (std::is_trivially_copyable<T>::value) {
          std::memcpy(inline_data, data_, sizeof(T) * size_);
        } else {
          for (size_t i = 0; i < size_; i++) {
            new (inline_data + i) T(std::move(data_[i]));
            data_[i].~T();
          }
        }

        std::free(data_);
        data_ = inline_data;
        capacity_ = InlineCapacity;
      } else if (size_ < capacity_) {
        reallocate(size_);
      }
    }
  }

  AETHON_ALWAYS_INLINE iterator begin() noexcept { return data_; }
  AETHON_ALWAYS_INLINE const_iterator begin() const noexcept { return data_; }
  AETHON_ALWAYS_INLINE const_iterator cbegin() const noexcept { return data_; }

  AETHON_ALWAYS_INLINE iterator end() noexcept { return data_ + size_; }
  AETHON_ALWAYS_INLINE const_iterator end() const noexcept {
    return data_ + size_;
  }
  AETHON_ALWAYS_INLINE const_iterator cend() const noexcept {
    return data_ + size_;
  }

  AETHON_ALWAYS_INLINE T &operator[](size_t index) noexcept {
    return data_[index];
  }

  AETHON_ALWAYS_INLINE const T &operator[](size_t index) const noexcept {
    return data_[index];
  }

  AETHON_ALWAYS_INLINE T &at(size_t index) {
    if (AETHON_UNLIKELY(index >= size_)) {
      throw std::out_of_range("SmallVector index out of range");
    }
    return data_[index];
  }

  AETHON_ALWAYS_INLINE T &front() noexcept { return data_[0]; }
  AETHON_ALWAYS_INLINE const T &front() const noexcept { return data_[0]; }

  AETHON_ALWAYS_INLINE T &back() noexcept { return data_[size_ - 1]; }
  AETHON_ALWAYS_INLINE const T &back() const noexcept {
    return data_[size_ - 1];
  }

  AETHON_ALWAYS_INLINE T *data() noexcept { return data_; }
  AETHON_ALWAYS_INLINE const T *data() const noexcept { return data_; }
  AETHON_ALWAYS_INLINE size_t size() const noexcept { return size_; }
  AETHON_ALWAYS_INLINE size_t capacity() const noexcept { return capacity_; }
  AETHON_ALWAYS_INLINE bool empty() const noexcept { return size_ == 0; }

  AETHON_ALWAYS_INLINE void clear() noexcept {
    if constexpr (!std::is_trivially_destructible<T>::value) {
      for (size_t i = 0; i < size_; ++i) {
        data_[i].~T();
      }
    }
    size_ = 0;
  }
  AETHON_ALWAYS_INLINE ~SmallVector() {
    clear();
    if (AETHON_UNLIKELY(!is_inline())) {
      std::free(data_);
    }
  }
};
} // namespace aethon
