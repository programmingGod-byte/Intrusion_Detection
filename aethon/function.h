#pragma once

#include "aethon/aethon.h"
#include <iostream>
#include <type_traits>
#include <utility>
#include <cstddef>
#include <new>

namespace aethon {

template <typename Signature>
class Function;

template <typename R, typename... Args>
class Function<R(Args...)> {
private:
    static constexpr size_t kInlineSize = 64;
    alignas(16) std::byte storage_[kInlineSize];

    using invoker_t = R(*)(void*, Args&&...);
    invoker_t invoker_{nullptr};

    using deleter_t = void(*)(void*);
    deleter_t deleter_{nullptr};

    void clear() {
        if (deleter_) {
            deleter_(storage_);
            deleter_ = nullptr;
        }
        invoker_ = nullptr;
    }

    void move_from(Function&& other) noexcept {
        invoker_ = other.invoker_;
        deleter_ = other.deleter_;

        if (other.deleter_) {
            for (size_t i = 0; i < kInlineSize; i++) {
                storage_[i] = other.storage_[i];
            }
            other.invoker_ = nullptr;
            other.deleter_ = nullptr;
        }
    }   

public:
    Function() = default;

    template <typename Callable, 
              typename = std::enable_if_t<!std::is_same_v<std::decay_t<Callable>, Function>>>
    Function(Callable&& callable) {
        using DecayCallable = std::decay_t<Callable>;

        AETHON_SAFE_CHECK(sizeof(DecayCallable) <= kInlineSize, "Lambda capture exceeds 64-byte inline storage");

        new (storage_) DecayCallable(std::forward<Callable>(callable));

        invoker_ = [](void* box_ptr, Args&&... args) -> R {
            auto* real_lambda = reinterpret_cast<DecayCallable*>(box_ptr);
            return (*real_lambda)(std::forward<Args>(args)...);
        };

        deleter_ = [](void* box_ptr) {
            auto* real_lambda = reinterpret_cast<DecayCallable*>(box_ptr);
            real_lambda->~DecayCallable();
        };
    }

    ~Function() {
        clear();
    }

    Function(const Function&) = delete;
    Function& operator=(const Function&) = delete;

    Function(Function&& other) noexcept {
        move_from(std::move(other));
    }

    Function& operator=(Function&& other) noexcept {
        if (this != &other) {
            clear();
            move_from(std::move(other));
        }
        return *this;
    }

    R operator()(Args... args) const {
        AETHON_SAFE_CHECK(invoker_ != nullptr, "Cannot call empty aethon::Function");
        return invoker_(const_cast<void*>(static_cast<const void*>(storage_)), std::forward<Args>(args)...);
    }

    explicit operator bool() const noexcept {
        return invoker_ != nullptr;
    }
};

} // namespace aethon
