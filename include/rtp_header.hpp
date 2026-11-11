#ifndef RTP_HEADER_HPP
#define RTP_HEADER_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace qualcomm_rtp {

// Host values only. Object size/layout is never used as a wire format.
struct RTPHeader {
    uint8_t version{2};
    uint8_t padding{0};
    uint8_t extension{0};
    uint8_t csrc_count{0};
    uint8_t marker{0};
    uint8_t payload_type{96};
    uint16_t sequence_number{0};
    uint32_t timestamp{0};
    uint32_t ssrc{0};

    static constexpr uint8_t DEFAULT_VERSION = 2;
    static constexpr uint8_t STREAM_PAYLOAD_TYPE = 96;
    static constexpr size_t FIXED_HEADER_SIZE = 12;
    using WireHeader = std::array<uint8_t, FIXED_HEADER_SIZE>;

    static bool serialize(const RTPHeader& h, uint8_t* out, size_t size) noexcept {
        if (!out || size < FIXED_HEADER_SIZE || h.version > 3 || h.padding > 1 ||
            h.extension > 1 || h.csrc_count > 15 || h.marker > 1 || h.payload_type > 127) {
            return false;
        }
        out[0] = static_cast<uint8_t>((h.version << 6) | (h.padding << 5) |
                                     (h.extension << 4) | h.csrc_count);
        out[1] = static_cast<uint8_t>((h.marker << 7) | h.payload_type);
        out[2] = static_cast<uint8_t>(h.sequence_number >> 8);
        out[3] = static_cast<uint8_t>(h.sequence_number & 0xffU);
        for (size_t i = 0; i < 4; ++i) {
            out[4 + i] = static_cast<uint8_t>((h.timestamp >> (24 - 8 * i)) & 0xffU);
            out[8 + i] = static_cast<uint8_t>((h.ssrc >> (24 - 8 * i)) & 0xffU);
        }
        return true;
    }

    static WireHeader serialize(const RTPHeader& h) noexcept {
        WireHeader out{};
        serialize(h, out.data(), out.size());
        return out;
    }

    // Decodes only the fixed header; parse_packet validates the entire packet.
    static bool deserialize(const uint8_t* src, size_t size, RTPHeader& h) noexcept {
        if (!src || size < FIXED_HEADER_SIZE) return false;
        h.version = static_cast<uint8_t>(src[0] >> 6);
        h.padding = static_cast<uint8_t>((src[0] >> 5) & 1U);
        h.extension = static_cast<uint8_t>((src[0] >> 4) & 1U);
        h.csrc_count = static_cast<uint8_t>(src[0] & 15U);
        h.marker = static_cast<uint8_t>(src[1] >> 7);
        h.payload_type = static_cast<uint8_t>(src[1] & 127U);
        h.sequence_number = static_cast<uint16_t>((static_cast<uint16_t>(src[2]) << 8) | src[3]);
        h.timestamp = 0;
        h.ssrc = 0;
        for (size_t i = 0; i < 4; ++i) {
            h.timestamp = (h.timestamp << 8) | src[4 + i];
            h.ssrc = (h.ssrc << 8) | src[8 + i];
        }
        return true;
    }

    static bool deserialize(const WireHeader& src, RTPHeader& h) noexcept {
        return deserialize(src.data(), src.size(), h);
    }

    // PT 96 is the application's negotiated format, not a universal RTP rule.
    static bool parse_packet(const uint8_t* src, size_t size, RTPHeader& h,
                             size_t& payload_offset, size_t& payload_size,
                             uint8_t expected_type = STREAM_PAYLOAD_TYPE) noexcept {
        if (!deserialize(src, size, h) || h.version != 2 || h.payload_type != expected_type) return false;
        size_t offset = FIXED_HEADER_SIZE + 4U * h.csrc_count;
        if (offset > size) return false;
        if (h.extension) {
            if (size - offset < 4) return false;
            const size_t words = (static_cast<size_t>(src[offset + 2]) << 8) | src[offset + 3];
            offset += 4;
            if (words > (size - offset) / 4) return false;
            offset += words * 4;
        }
        size_t end = size;
        if (h.padding) {
            if (end == offset) return false;
            const size_t padding_size = src[end - 1];
            if (padding_size == 0 || padding_size > end - offset) return false;
            end -= padding_size;
        }
        payload_offset = offset;
        payload_size = end - offset;
        return true;
    }
};

// Portable signed distance for windows smaller than half the sequence space.
inline int sequence_distance(uint16_t seq, uint16_t expected) noexcept {
    const unsigned delta = (static_cast<unsigned>(seq) + 65536U - expected) & 0xffffU;
    return delta < 32768U ? static_cast<int>(delta) : static_cast<int>(delta) - 65536;
}
}
using RTPHeader = qualcomm_rtp::RTPHeader;
#endif
