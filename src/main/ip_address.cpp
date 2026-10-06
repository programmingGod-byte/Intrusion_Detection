#pragma once
#include "aethon/aethon.h"
#include <cstddef>
#include <cstdint>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
namespace aethon {

    struct alignas(implementation::hardware_destructive_interference_size) HostIpTable{
        uint32_t ips[8]{0}; // up to 8 local ips
        uint8_t count{0};

        AETHON_ALWAYS_INLINE bool contains(uint32_t ip) const noexcept {
            for (uint8_t i = 0; i<count; ++i) {
                if(ips[i]==ip) return true;
            }
            return false;
        }
    };

    inline HostIpTable g_host_ips;

    inline void load_interface_ips(const char * __restrict__ ifname) noexcept{
        struct ifaddrs * ifaddr = nullptr;
        if(AETHON_UNLIKELY(getifaddrs(&ifaddr))==-1){
            AETHON_SAFE_CHECK(Trait::always_false<bool>,"cannot able to get the interface address \n");
            return;
        }

        g_host_ips.count = 0;
         for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if(!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET){
                continue;
            }

            if(std::memcmp(ifa->ifa_name,ifname,IFNAMSIZ)==0){
                if(AETHON_LIKELY(g_host_ips.count < 8)){
                    const auto *sa = reinterpret_cast<const struct sockaddr_in *>(ifa->ifa_addr);
                    g_host_ips.ips[g_host_ips.count++] = sa->sin_addr.s_addr;
        
                    char ip_str[INET_ADDRSTRLEN];
                    // convert binary ip address to human readle adres
                    inet_ntop(AF_INET, &sa->sin_addr.s_addr, ip_str, sizeof(ip_str));
                    std::cout << "[Network] Monitoring Interface IP: " << ip_str << "\n";
                }
            }
         }

         freeifaddrs(ifaddr);
    }
};  