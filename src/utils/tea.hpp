#pragma once

#include "byte_packet.hpp"

namespace shitsu::utils {

    static constexpr inline int n = 16;
    static constexpr inline unsigned int delta = 0x9e3779b9;

    class tea_cipher {
    public:
        unsigned int k1;
        unsigned int k2;
        unsigned int k3;
        unsigned int k4;

        tea_cipher(unsigned int k1, unsigned int k2, unsigned int k3, unsigned int k4) : k1(k1), k2(k2), k3(k3), k4(k4) {}

        explicit tea_cipher(const void *k) {
            memcpy(this, k, sizeof(tea_cipher));
        }

        operator unsigned int *() {
            return reinterpret_cast<unsigned int *>(this);
        }

        std::unique_ptr<byte_packet_builder> encrypt(const void *input, size_t len);

        std::unique_ptr<byte_packet_builder> decrypt(const void *input, size_t len);
    };
}
