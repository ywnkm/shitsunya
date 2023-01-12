#include "tea.hpp"
#include <bit>

namespace shitsu::utils {

    static void tea_encrypt(unsigned int *v, unsigned int *k) {
        unsigned int v0 = v[0], v1 = v[1];
        if constexpr (std::endian::native == std::endian::little) {
            v0 = std::byteswap(v0);
            v1 = std::byteswap(v1);
        }
        unsigned int sum = 0, i;
        for (i = 0; i < n; i++) {
            sum += delta;
            v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
            v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        }
        if constexpr (std::endian::native == std::endian::little) {
            v[0] = std::byteswap(v0);
            v[1] = std::byteswap(v1);
        } else {
            v[0] = v0;
            v[1] = v1;
        }
    }

    static void tea_encrypt_b(unsigned char *v, unsigned int *k, unsigned char *out) {
        unsigned int uv[2];
        memcpy(uv, v, 8);
        tea_encrypt(uv, k);
        memcpy(out, uv, 8);
    }

    static void tea_decrypt(unsigned int *v, unsigned int *k) {
        unsigned int v0 = v[0], v1 = v[1];
        if constexpr (std::endian::native == std::endian::little) {
            v0 = std::byteswap(v0);
            v1 = std::byteswap(v1);
        }
        unsigned int sum = 0xE3779B90, i;
        for (i = 0; i < n; i++) {
            v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
            v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
            sum -= delta;
        }
        if constexpr (std::endian::native == std::endian::little) {
            v[0] = std::byteswap(v0);
            v[1] = std::byteswap(v1);
        } else {
            v[0] = v0;
            v[1] = v1;
        }
    }

    static void tea_decrypt_b(unsigned char *v, unsigned int *k, unsigned char *out) {
        unsigned int uv[2];
        memcpy(uv, v, 8);
        tea_decrypt(uv, k);
        memcpy(out, uv, 8);
    }

    std::unique_ptr<byte_packet_builder> tea_cipher::encrypt(const void *input, size_t len) {
        auto builder = std::make_unique<byte_packet_builder>();
        if (input == nullptr || len == 0) [[unlikely]] return builder;
        unsigned char plain[8], prePlain[8];
        int pos = 1;
        int padding = 0;
        int crypt = 0, preCrypt = 0;
        bool head = true;
        pos = (len + 0x0A) % 8;
        if (pos != 0) {
            pos = 8 - pos;
        }
        size_t tempSize = len + pos + 10;
        auto *temp = new unsigned char[tempSize];
        memset(temp, 0, tempSize);
        auto encrypt8Bytes = [&]() mutable -> void {
            for (pos = 0; pos < 8; pos++) {
                if (head)
                    plain[pos] ^= prePlain[pos];
                else [[likely]]
                plain[pos] ^= temp[preCrypt + pos];
            }
            tea_encrypt_b(plain, *this, (temp + crypt));
            for (pos = 0; pos < 8; pos++) {
                temp[crypt + pos] ^= prePlain[pos];
            }
            memcpy(prePlain, plain, 8);
            preCrypt = crypt;
            crypt += 8;
            pos = 0;
            head = false;
        };
        plain[0] = (unsigned char)((rand() & 0xF8) | pos);

        for (int i = 1; i <= pos; i++) {
            plain[i] = (unsigned char) (rand() & 0xFF);
        }
        pos++;
        for (unsigned char & i : prePlain) {
            i = 0;
        }
        padding = 1;
        while (padding <= 2) {
            if (pos < 8) {
                plain[pos++] = (unsigned char) (rand() & 0xFF);
                padding++;
            }
            if (pos == 8) {
                encrypt8Bytes();
            }
        }

        int i = 0;
        while (len > 0) {
            if (pos < 8) {
                plain[pos++] = ((unsigned char *) input)[i++];
                len--;
            }
            if (pos == 8) {
                encrypt8Bytes();
            }
        }
        padding = 1;
        while (padding <= 7) {
            if (pos < 8) {
                plain[pos++] = 0;
                padding++;
            }
            if (pos == 8) {
                encrypt8Bytes();
            }
        }
        // ret.write(temp, tempSize);
        builder->write(temp, tempSize);
        delete[] temp;
        return builder;
    }

    std::unique_ptr<byte_packet_builder> tea_cipher::decrypt(const void *input, size_t len) {
        auto builder = std::make_unique<byte_packet_builder>();
        if (input == nullptr || len == 0) [[unlikely]] return builder;
        if ((len % 8 != 0) || len < 16) [[unlikely]] return builder;
        int crypt = 0, preCrypt = 0;
        int count;
        unsigned char plain[8], prePlain[8];
        tea_decrypt_b((unsigned char *) input, *this, prePlain);
        int pos = prePlain[0] & 0x07;
        count = len - pos - 10;
        if (count < 0) [[unlikely]] return builder;
        auto temp = std::unique_ptr<unsigned char>(new unsigned char[count]);
        size_t tempSize = count;
        crypt = 8;
        int contextStart = 8;
        pos++;
        int padding = 1;
        unsigned char m1[8];
        memset(m1, 0, 8);
        unsigned char *m = m1;

        auto decrypt8Bytes = [&](unsigned char *in, int len) mutable -> bool {
            for (pos = 0; pos < 8; pos++) {
                if (contextStart + pos >= len) return true;
                prePlain[pos] ^= in[crypt + pos];
            }
            tea_decrypt_b(prePlain, *this, prePlain);

            contextStart += 8;
            crypt += 8;
            pos = 0;
            return true;
        };

        while (padding <= 2) {
            if (pos < 8) {
                pos++;
                padding++;
            }
            if (pos == 8) {
                // *m = (u_char *)input;
                m = (unsigned char *)input;
                if (!decrypt8Bytes((unsigned char *)input, len)) {
                    return builder;
                };
            }
        }

        int i = 0;
        while (count != 0) {
            if (pos < 8) {
                temp.get()[i] = (unsigned char) (m[preCrypt + pos] ^ prePlain[pos]);
                i++;
                count--;
                pos++;
            }
            if (pos == 8) {
                m = (unsigned char *)input;
                preCrypt = crypt - 8;
                if (!decrypt8Bytes((unsigned char *)input, len)) {
                    return builder;
                }
            }
        }

        for (padding = 1; padding < 8; padding++) {
            if (pos < 8) {
                if (((m)[preCrypt + pos] ^ prePlain[pos]) != 0) {
                    return builder;
                }
                pos++;
            }
            if (pos == 8) {
                m = (unsigned char *)input;
                preCrypt = crypt;

                if (!decrypt8Bytes((unsigned char *)input, len)) {
                    return builder;
                }
            }
        }
        builder->write(temp.get(), tempSize);
        return builder;
    }
}
