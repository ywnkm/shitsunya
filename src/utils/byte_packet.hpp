#pragma once

#include <asio.hpp>
#include <bit>
#include <memory>
#include <string>

namespace shitsu::utils {

    class byte_packet_builder;

    class byte_read_packet;

    class byte_packet_builder {
    public:

        byte_packet_builder() = default;

        template<typename T>
        requires std::is_integral_v<T>
        void write_number(const T &&number, const std::endian &endian = std::endian::native) {
            constexpr size_t size = sizeof(T);
            T num = number;
            if (endian != std::endian::native)
                num = std::byteswap(num);

            auto p = buffer.prepare(size);
            std::memcpy(p.data(), &num, size);
            buffer.commit(size);
        }

        template<typename T>
        requires std::is_floating_point_v<T>
        void write_number(const T &&number, const std::endian &endian = std::endian::native) {
            constexpr size_t size = sizeof(T);
            T num = number;
            if (endian != std::endian::native) {
                size_t temp = std::byteswap(*reinterpret_cast<size_t *>(&num));
                num = *reinterpret_cast<T *>(&temp);
            }

            auto p = buffer.prepare(size);
            std::memcpy(p.data(), &num, size);
            buffer.commit(size);
        }

        template<typename T>
        requires std::is_integral_v<T> || std::is_floating_point_v<T>
        byte_packet_builder &operator<<(const T &&number) {
            write_number<T>(number);
            return *this;
        }

        void write(const void *data, size_t len) {
            auto p = buffer.prepare(len);
            std::memcpy(p.data(), data, len);
            buffer.commit(len);
        }

        [[nodiscard]]
        size_t size() const {
            return buffer.size();
        }

        [[nodiscard]]
        const void *get_data() const {
            return buffer.data().data();
        }

        [[nodiscard]]
        std::unique_ptr<char> build() {
            char *d = new char[buffer.size()];
            std::memcpy(d, buffer.data().data(), buffer.size());
            return std::unique_ptr<char>(d);
        }


        [[nodiscard]]
        std::string hex_string(size_t len = 0) {
            if (len == 0) len = buffer.size();
            std::string str;
            auto *data = reinterpret_cast<const unsigned char *>(buffer.data().data());
            for (size_t i = 0; i < len; i++) {
                char buf[4];
                sprintf(buf, "%02x ", data[i]);
                str.append(buf);
            }
            return str;
        }

    private:
        asio::streambuf buffer;
    };

    class byte_read_packet {
    public:
        explicit byte_read_packet(const void *data, size_t len) {
            auto p = buffer.prepare(len);
            std::memcpy(p.data(), data, len);
            buffer.commit(len);
        }

        template<typename T>
        requires std::is_integral_v<T>
        T read_number(const std::endian &endian = std::endian::native) {
            constexpr size_t size = sizeof(T);
            T num;
            auto is = buffer.data();
            std::memcpy(&num, asio::buffer_cast<const void *>(is), size);
            buffer.consume(size);
            if (endian != std::endian::native)
                num = std::byteswap(num);
            return num;
        }

        template<typename T>
        requires std::is_floating_point_v<T>
        T read_number(const std::endian &endian = std::endian::native) {
            constexpr size_t size = sizeof(T);
            T num;
            auto is = buffer.data();
            std::memcpy(&num, asio::buffer_cast<const void *>(is), size);
            buffer.consume(size);
            if (endian != std::endian::native) {
                size_t temp = std::byteswap(*reinterpret_cast<size_t *>(&num));
                num = *reinterpret_cast<T *>(&temp);
            }
            return num;
        }

        [[nodiscard]]
        size_t size() const {
            return buffer.size();
        }


    private:
        asio::streambuf buffer;
    };
}