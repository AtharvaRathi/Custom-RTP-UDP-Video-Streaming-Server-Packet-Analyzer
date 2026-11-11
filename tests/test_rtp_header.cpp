#include "rtp_header.hpp"
#include <cstdlib>
#include <iostream>
#include <vector>

// Remains active in Release builds.
#define CHECK(expr) do { if (!(expr)) { std::cerr << "Failed at line " << __LINE__ << ": " #expr "\n"; return EXIT_FAILURE; } } while (false)

int main() {
    RTPHeader h{};
    h.marker = 1;
    h.sequence_number = 10001;
    h.timestamp = 3600000;
    h.ssrc = 0x12345678;
    const RTPHeader::WireHeader expected = {0x80, 0xe0, 0x27, 0x11, 0x00, 0x36, 0xee, 0x80, 0x12, 0x34, 0x56, 0x78};
    CHECK(RTPHeader::serialize(h) == expected);
    RTPHeader parsed{};
    CHECK(RTPHeader::deserialize(expected, parsed));
    CHECK(parsed.sequence_number == h.sequence_number && parsed.timestamp == h.timestamp && parsed.ssrc == h.ssrc);
    CHECK(parsed.version == 2 && parsed.marker == 1 && parsed.payload_type == 96);
    for (size_t n = 0; n < 12; ++n) {
        CHECK(!RTPHeader::deserialize(expected.data(), n, parsed));
        uint8_t out[12]{};
        CHECK(!RTPHeader::serialize(h, out, n));
    }
    CHECK(!RTPHeader::deserialize(nullptr, 12, parsed));
    CHECK(!RTPHeader::serialize(h, nullptr, 12));
    h.csrc_count = 16;
    uint8_t out[12]{};
    CHECK(!RTPHeader::serialize(h, out, 12));

    size_t offset = 0, size = 0;
    // One CSRC, one-word extension, two payload bytes, four padding bytes.
    std::vector<uint8_t> packet(expected.begin(), expected.end());
    packet[0] = 0xb1;
    packet.insert(packet.end(), {0,0,0,1, 0xbe,0xde,0,1, 1,2,3,4, 0xaa,0xbb, 0,0,0,4});
    CHECK(RTPHeader::parse_packet(packet.data(), packet.size(), parsed, offset, size));
    CHECK(offset == 24 && size == 2 && packet[offset] == 0xaa);
    for (size_t n = 0; n <= 24; ++n) CHECK(!RTPHeader::parse_packet(packet.data(), n, parsed, offset, size));
    packet.back() = 0;
    CHECK(!RTPHeader::parse_packet(packet.data(), packet.size(), parsed, offset, size));
    packet.back() = 7;
    CHECK(!RTPHeader::parse_packet(packet.data(), packet.size(), parsed, offset, size));
    packet.back() = 4;
    packet[19] = 255;
    CHECK(!RTPHeader::parse_packet(packet.data(), packet.size(), parsed, offset, size));
    packet[19] = 1;
    packet[0] = 0x71;
    CHECK(!RTPHeader::parse_packet(packet.data(), packet.size(), parsed, offset, size));
    packet[0] = 0xb1;
    packet[1] = 97;
    CHECK(!RTPHeader::parse_packet(packet.data(), packet.size(), parsed, offset, size));
    CHECK(qualcomm_rtp::sequence_distance(0, 65535) == 1);
    CHECK(qualcomm_rtp::sequence_distance(65535, 0) == -1);
    std::cout << "RTP byte encoding and packet validation tests passed\n";
}
