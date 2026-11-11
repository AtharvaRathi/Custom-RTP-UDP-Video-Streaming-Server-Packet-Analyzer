#include "rtp_header.hpp"
#include "posix_utils.hpp"
#include <algorithm>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <thread>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <vector>

/**
 * @brief High-performance POSIX UDP Real-Time Transport Protocol (RTP) Server.
 *
 * Implements strict RFC 3550 packetization and transmission over POSIX UDP sockets
 * with 30 FPS frame pacing for real-time video streaming.
 */
class RTPServer {
public:
    static constexpr size_t   RTP_PAYLOAD_CHUNK_SIZE = 1400; ///< Safe MTU limit (1500 - 20 IP - 8 UDP - 12 RTP = 1460 max)
    static constexpr uint32_t TIMESTAMP_INCREMENT    = 3000; ///< 90 kHz clock / 30 fps = 3000 ticks per frame
    static constexpr uint8_t  DEFAULT_PAYLOAD_TYPE   = 96;   ///< RFC 3551 dynamic payload type (e.g. H.264 video)
    static constexpr uint32_t DEFAULT_SSRC           = 0x10203040; ///< Default synchronization source identifier

    /**
     * @brief Construct a new RTPServer and initialize the underlying POSIX UDP socket.
     * @throws std::runtime_error If socket creation fails.
     */
    RTPServer() {
        socket_fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error(std::string("Failed to initialize POSIX UDP socket: ") + std::strerror(errno));
        }

        // Optional: configure socket send buffer for high-throughput video bursts
        int send_buf_size = 1024 * 1024; // 1 MB buffer
        ::setsockopt(socket_fd_, SOL_SOCKET, SO_SNDBUF, &send_buf_size, sizeof(send_buf_size));
    }

    /**
     * @brief Clean up and close socket descriptor.
     */
    ~RTPServer() {
        if (socket_fd_ >= 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
        }
    }

    // Disable copy semantics to prevent socket fd aliasing
    RTPServer(const RTPServer&) = delete;
    RTPServer& operator=(const RTPServer&) = delete;

    // Enable move semantics
    RTPServer(RTPServer&& other) noexcept : socket_fd_(other.socket_fd_) {
        other.socket_fd_ = -1;
    }

    RTPServer& operator=(RTPServer&& other) noexcept {
        if (this != &other) {
            if (socket_fd_ >= 0) {
                ::close(socket_fd_);
            }
            socket_fd_ = other.socket_fd_;
            other.socket_fd_ = -1;
        }
        return *this;
    }

    /**
     * @brief Streams binary media file to target destination over RTP/UDP with 30 FPS pacing.
     *
     * @param filepath  Path to media file.
     * @param dest_ip   Target IPv4 address (e.g. "127.0.0.1").
     * @param dest_port Target UDP port (e.g. 5004).
     */
    void stream_media(const std::string& filepath, const std::string& dest_ip, int dest_port) {
        if (socket_fd_ < 0) {
            throw std::runtime_error("Cannot stream: UDP socket is not initialized");
        }

        // 1. Prepare destination sockaddr_in
        struct sockaddr_in dest_addr;
        std::memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(static_cast<uint16_t>(dest_port));

        if (::inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0) {
            throw std::invalid_argument("Invalid destination IPv4 address: " + dest_ip);
        }

        // 2. Open binary input file
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open binary media file: " + filepath);
        }

        std::cout << "[RTPServer] Initiating stream:\n"
                  << "  Source File:        " << filepath << "\n"
                  << "  Destination:        " << dest_ip << ":" << dest_port << "\n"
                  << "  Chunk Size:         " << RTP_PAYLOAD_CHUNK_SIZE << " bytes\n"
                  << "  Pacing:             33 ms (~30 FPS)\n"
                  << "  Timestamp Step:     " << TIMESTAMP_INCREMENT << " (90kHz clock)\n"
                  << "--------------------------------------------------------" << std::endl;

        // 3. Pre-allocate packet buffer: 12-byte RTP header + 1400-byte payload = 1412 bytes max
        constexpr size_t MAX_PACKET_SIZE = RTPHeader::FIXED_HEADER_SIZE + RTP_PAYLOAD_CHUNK_SIZE;
        uint8_t packet_buffer[MAX_PACKET_SIZE];
        uint8_t* payload_ptr = packet_buffer + RTPHeader::FIXED_HEADER_SIZE;

        // 4. Stream state variables
        uint16_t sequence_number = 0;
        uint32_t timestamp = 0;
        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;

        // 5. Read binary file in 1400-byte chunks and stream
        while (posix_utils::running && (file.read(reinterpret_cast<char*>(payload_ptr), RTP_PAYLOAD_CHUNK_SIZE) || file.gcount() > 0)) {
            std::streamsize bytes_read = file.gcount();
            if (bytes_read <= 0) {
                break;
            }

            // Populate RFC 3550 RTP Header in host byte order
            RTPHeader header{};
            header.version         = 2;
            header.padding         = 0;
            header.extension       = 0;
            header.csrc_count      = 0;
            header.marker          = (file.peek() == EOF) ? 1 : 0; // Set marker on terminal chunk
            header.payload_type    = DEFAULT_PAYLOAD_TYPE;
            header.sequence_number = sequence_number;
            header.timestamp       = timestamp;
            header.ssrc            = DEFAULT_SSRC;

            // Serialize header to network byte order directly at the beginning of packet_buffer
            if (!RTPHeader::serialize(header, packet_buffer, sizeof(packet_buffer))) {
                throw std::runtime_error("Failed to serialize RTP header");
            }

            const size_t packet_length = RTPHeader::FIXED_HEADER_SIZE + static_cast<size_t>(bytes_read);

            // Transmit packet via POSIX sendto()
            ssize_t bytes_sent;
            do {
                bytes_sent = ::sendto(
                    socket_fd_,
                    packet_buffer,
                    packet_length,
                    0,
                    reinterpret_cast<const struct sockaddr*>(&dest_addr),
                    sizeof(dest_addr)
                );
            } while (bytes_sent < 0 && errno == EINTR && posix_utils::running);
            if (!posix_utils::running) break;

            if (bytes_sent < 0) {
                throw std::runtime_error(std::string("sendto failed: ") + std::strerror(errno));
            } else {
                total_packets++;
                total_bytes += static_cast<uint64_t>(bytes_sent);

                // Periodic telemetry reporting
                if (total_packets % 30 == 0 || total_packets == 1) {
                    std::cout << "[RTPServer] Sent Packet #" << total_packets
                              << " | Seq: " << sequence_number
                              << " | TS: " << timestamp
                              << " | Length: " << bytes_sent << " bytes" << std::endl;
                }
            }

            // Update stream state for next chunk
            sequence_number++;
            timestamp += TIMESTAMP_INCREMENT;

            // Pacing: 33ms per packet (~30 FPS real-time transmission)
            std::this_thread::sleep_for(std::chrono::milliseconds(33));
        }

        if (!posix_utils::running) throw std::runtime_error("Streaming interrupted");
        if (file.bad()) throw std::runtime_error("Failed to read input file");

        std::cout << "--------------------------------------------------------\n"
                  << "[RTPServer] Streaming completed successfully.\n"
                  << "  Total Packets Sent: " << total_packets << "\n"
                  << "  Total Bytes Sent:   " << total_bytes << " bytes\n"
                  << "  Final Seq Number:   " << (sequence_number > 0 ? sequence_number - 1 : 0) << "\n"
                  << "  Final Timestamp:    " << (timestamp >= TIMESTAMP_INCREMENT ? timestamp - TIMESTAMP_INCREMENT : 0) << std::endl;
    }

private:
    int socket_fd_{-1};
};

/**
 * @brief Helper to generate a dummy synthetic video payload file for testing if none is provided.
 */
static void create_dummy_media_file_if_missing(const std::string& path, size_t size_bytes = 1400 * 60) {
    std::ifstream check(path, std::ios::binary);
    if (check.is_open()) {
        return; // File already exists
    }

    std::cout << "[RTPServer] Generating sample video payload file (" << size_bytes << " bytes): "
              << path << std::endl;
    std::ofstream out(path, std::ios::binary);
    std::vector<uint8_t> dummy_frame(1400);

    for (size_t i = 0; i < dummy_frame.size(); ++i) {
        dummy_frame[i] = static_cast<uint8_t>((i % 256));
    }

    size_t written = 0;
    while (written < size_bytes) {
        size_t to_write = std::min(dummy_frame.size(), size_bytes - written);
        out.write(reinterpret_cast<const char*>(dummy_frame.data()), static_cast<std::streamsize>(to_write));
        written += to_write;
    }
}

int main(int argc, char* argv[]) {
    try {
        posix_utils::install_shutdown_handlers();
        std::string filepath  = "sample_video.bin";
        std::string dest_ip   = "127.0.0.1";
        int dest_port         = 5004;

        if (argc >= 2) {
            std::string arg1 = argv[1];
            if (arg1 == "-h" || arg1 == "--help") {
                std::cout << "Usage: " << argv[0] << " [filepath] [dest_ip] [dest_port]\n"
                          << "  filepath   : Path to binary media file (default: sample_video.bin)\n"
                          << "  dest_ip    : Destination IPv4 address (default: 127.0.0.1)\n"
                          << "  dest_port  : Destination UDP port (default: 5004)\n";
                return 0;
            }
            filepath = arg1;
        }
        if (argc >= 3) {
            dest_ip = argv[2];
        }
        if (argc >= 4) {
            dest_port = posix_utils::parse_port(argv[3]);
        }

        // Ensure sample media file exists for out-of-the-box streaming demonstration
        create_dummy_media_file_if_missing(filepath);

        RTPServer server;
        server.stream_media(filepath, dest_ip, dest_port);
    } catch (const std::exception& ex) {
        std::cerr << "[RTPServer] Fatal Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
