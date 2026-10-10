#pragma once
#include "../../aethon/aethon.h"
#include "hs_common.h"
#include "hs_runtime.h"
#include "rule_parser.h"
#include <cstddef>
#include <hs/hs.h>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <functional>
#include "../../aethon/function.h"
#include "../../aethon/single_thread_hasmap.h"

namespace aethon {
    namespace scan {
        

        struct AttackAlert {
            uint32_t sid{0};
            const rules::AethonRule *rule{nullptr};
            uint64_t match_offset{0};
            const uint8_t *payload{nullptr};
            size_t payload_len{0};
        };

        using AlertCallback = aethon::Function<void(const AttackAlert &)>;


        class alignas(implementation::hardware_destructive_interference_size)
        HyperscanEngine{
            private:
                 using RuleMap = aethon::SingleThreadHashMap<uint32_t, const rules::AethonRule*, 0>;

                hs_database_t * db_{nullptr};
                hs_scratch_t * scratch_{nullptr};

                std::unique_ptr<RuleMap> rule_map_{nullptr};
                AlertCallback alert_cb_{};

                // internal match context passed to hyperscan c call bacl

                struct MatchContext{
                    HyperscanEngine *engine{nullptr};
                    const uint8_t * payload{nullptr};

                    size_t payload_len{0};

                    size_t match_count{0};
                };


                // callback invoked bu hyper scan hardware scanner

                static int on_match_event(unsigned int id, unsigned long long from,unsigned long long to, unsigned int flags,void *context) noexcept{
                    auto *ctx = reinterpret_cast<MatchContext *>(context);
                    if(AETHON_LIKELY(ctx && ctx->engine)){
                        ctx->match_count++;
                        if(ctx->engine->alert_cb_){
                            AttackAlert alert;
                            alert.sid  = id;
                            alert.match_offset = to;
                            alert.payload = ctx->payload;
                            alert.payload_len = ctx->payload_len;

                            if(AETHON_LIKELY(ctx->engine->rule_map_)){
                                const rules::AethonRule **found  = ctx->engine->rule_map_->find(id);
                                if(AETHON_LIKELY(found!=nullptr)){
                                    alert.rule = *found;
                                }
                            }

                            ctx->engine->alert_cb_(alert);
                        }
                    }
                    return 0; // continue scaaning for additional matching patterns
                }

                static size_t next_power_of_two(size_t n) noexcept {
                    if (n < 64) return 64;
                    --n;
                    n |= n >> 1;
                    n |= n >> 2;
                    n |= n >> 4;
                    n |= n >> 8;
                    n |= n >> 16;
                    n |= n >> 32;
                    return n + 1;
                }

            public:
                HyperscanEngine() = default;
                ~HyperscanEngine(){
                    clear();
                }

                void clear() noexcept{
                    if(scratch_){
                        hs_free_scratch(scratch_);
                        scratch_ = nullptr;
                    }
                    if(db_){
                        hs_free_database(db_);
                        db_ = nullptr;
                    }
                }

                HyperscanEngine(const HyperscanEngine &) = delete;
                HyperscanEngine &operator=(const HyperscanEngine&) = delete;

                void set_alert_callback(AlertCallback cb) noexcept {
                   alert_cb_ = std::move(cb);
                }
                
        };
    };
};