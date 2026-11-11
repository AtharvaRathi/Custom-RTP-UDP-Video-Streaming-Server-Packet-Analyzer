#include "rtp_header.hpp"
#include "posix_utils.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <csignal>

#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <sys/uio.h>

/**
 * @brief High-performance POSIX UDP Real-Time Transport Protocol (RTP) Client.
 *
 * Implements a jitter/reordering buffer to handle out-of-order RTP datagrams,
 * reconstructs contiguous media streams, and features a 500ms drop timeout to
 * prevent stream stalling.
 */
class RTPClient {
public:
    static constexpr size_t   MAX_BUFFER_SIZE      = 2048; ///< Maximum expected UDP datagram size
    static constexpr size_t   MAX_JITTER_PACKETS   = 64;
    static constexpr int64_t  DROP_TIMEOUT_MS      = 500;  ///< Missing packet drop threshold in milliseconds
    static constexpr uint8_t  DEFAULT_PAYLOAD_TYPE = 96;   ///< Expected RFC 3551 dynamic video payload type

    /**
     * @brief Construct an RTPClient and bind a UDP socket to listening_port.
     *
     * @param listening_port Port on which to listen for incoming RTP UDP datagrams.
     * @throws std::runtime_error If socket creation or binding fails.
     */
    explicit RTPClient(int listening_port) : port_(listening_port) {
        socket_fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error(std::string("Failed to create UDP socket: ") + std::strerror(errno));
        }

        // Enable address reuse
        int opt_reuse = 1;
        if (::setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt_reuse, sizeof(opt_reuse)) < 0) {
            std::cerr << "[RTPClient] Warning: setsockopt SO_REUSEADDR failed: "
                      << std::strerror(errno) << std::endl;
        }

        // Configure receive buffer size (2 MB) to handle bursts
        int rcv_buf_size = 2 * 1024 * 1024;
        ::setsockopt(socket_fd_, SOL_SOCKET, SO_RCVBUF, &rcv_buf_size, sizeof(rcv_buf_size));

        // Configure 50ms socket read timeout so recvmsg doesn't block indefinitely,
        // allowing periodic evaluation of the 500ms missing packet timeout.
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000; // 50,000 microseconds = 50 ms
        if (::setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            std::cerr << "[RTPClient] Warning: setsockopt SO_RCVTIMEO failed: "
                      << std::strerror(errno) << std::endl;
        }

        // Bind socket to listening port on all IPv4 interfaces (0.0.0.0)
        struct sockaddr_in bind_addr;
        std::memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family      = AF_INET;
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        bind_addr.sin_port        = htons(static_cast<uint16_t>(listening_port));

        if (::bind(socket_fd_, reinterpret_cast<const struct sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
            throw std::runtime_error(std::string("Failed to bind UDP socket to port ") +
                                     std::to_string(listening_port) + ": " + std::strerror(errno));
        }

        std::cout << "[RTPClient] Successfully bound UDP socket to port " << listening_port << std::endl;
    }

    /**
     * @brief Destructor closes the socket file descriptor.
     */
    ~RTPClient() {
        if (socket_fd_ >= 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
        }
    }

    // Disable copy semantics
    RTPClient(const RTPClient&) = delete;
    RTPClient& operator=(const RTPClient&) = delete;

    // Move semantics
    RTPClient(RTPClient&& other) noexcept
        : socket_fd_(other.socket_fd_), port_(other.port_) {
        other.socket_fd_ = -1;
    }

    RTPClient& operator=(RTPClient&& other) noexcept {
        if (this != &other) {
            if (socket_fd_ >= 0) {
                ::close(socket_fd_);
            }
            socket_fd_ = other.socket_fd_;
            port_ = other.port_;
            other.socket_fd_ = -1;
        }
        return *this;
    }

    /**
     * @brief Continuous receive loop capturing RTP datagrams, reordering them via
     * a jitter buffer, writing contiguous chunks to output_filepath, and dropping
     * missing frames after 500ms.
     *
     * @param output_filepath Filepath to write reassembled media stream.
     */
    void start_receive_loop(const std::string& output_filepath) {
        std::ofstream out_file(output_filepath, std::ios::binary | std::ios::trunc);
        if (!out_file.is_open()) {
            throw std::runtime_error("Failed to open output file: " + output_filepath);
        }

        std::cout << "[RTPClient] Listening for RTP stream on port " << port_ << "...\n"
                  << "  Output File:        " << output_filepath << "\n"
                  << "  Drop Timeout:       " << DROP_TIMEOUT_MS << " ms\n"
                  << "--------------------------------------------------------" << std::endl;

        uint8_t recv_buffer[MAX_BUFFER_SIZE];
        struct sockaddr_in sender_addr;


        uint16_t expected_seq = 0;
        bool first_packet_received = false;
        std::chrono::steady_clock::time_point missing_seq_start_time;
        bool missing_timer_active = false;

        // Jitter Buffer: keyed by sequence number
        std::map<uint16_t, std::vector<uint8_t>> jitter_buffer;

        uint64_t total_packets_received = 0;
        uint64_t total_bytes_written = 0;
        uint64_t dropped_packets_count = 0;

        while (posix_utils::running) {
            // Check for missing packet timeout (500ms threshold)
            if (missing_timer_active) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - missing_seq_start_time).count();

                if (elapsed_ms >= DROP_TIMEOUT_MS) {
                    std::cout << "\033[33m[RTPClient] Packet Dropped: Sequence Number "
                              << expected_seq << " missing for " << elapsed_ms
                              << "ms (> " << DROP_TIMEOUT_MS << "ms). Dropping frame.\033[0m"
                              << std::endl;

                    dropped_packets_count++;
                    missing_timer_active = false;
                    expected_seq++; // Advance sequence number to prevent stream stall

                    // Flush any contiguous buffered packets starting at new expected_seq
                    flush_jitter_buffer(jitter_buffer, expected_seq, out_file,
                                        total_bytes_written, missing_timer_active,
                                        missing_seq_start_time);
                }
            }

            // Capture incoming datagram
            struct iovec iov{};
            iov.iov_base = recv_buffer;
            iov.iov_len = sizeof(recv_buffer);
            struct msghdr message{};
            message.msg_name = &sender_addr;
            message.msg_namelen = sizeof(sender_addr);
            message.msg_iov = &iov;
            message.msg_iovlen = 1;
            const ssize_t bytes_recv = ::recvmsg(socket_fd_, &message, 0);

            if (bytes_recv < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    // Socket timeout: loop continues to re-evaluate drop timeout and shutdown flag
                    continue;
                }
                std::cerr << "[RTPClient] recvmsg error: " << std::strerror(errno) << std::endl;
                continue;
            }

            if ((message.msg_flags & MSG_TRUNC) != 0) {
                std::cerr << "[RTPClient] Dropping truncated UDP datagram\n";
                continue;
            }
            RTPHeader header{};
            size_t payload_offset = 0;
            size_t payload_len = 0;
            if (!RTPHeader::parse_packet(recv_buffer, static_cast<size_t>(bytes_recv),
                                         header, payload_offset, payload_len)) {
                std::cerr << "[RTPClient] Dropping invalid RTP packet\n";
                continue;
            }
            total_packets_received++;
            const uint8_t* payload_ptr = recv_buffer + payload_offset;
            std::vector<uint8_t> payload(payload_ptr, payload_ptr + payload_len);

            // Establish initial baseline on first received packet
            if (!first_packet_received) {
                expected_seq = header.sequence_number;
                first_packet_received = true;
                missing_timer_active = false;
                std::cout << "[RTPClient] First packet detected: Initial Seq = "
                          << expected_seq << ", Timestamp = " << header.timestamp
                          << ", SSRC = 0x" << std::hex << header.ssrc << std::dec << std::endl;
            }

            // Sequence comparison taking 16-bit unsigned modular wrap-around into account
            int diff = qualcomm_rtp::sequence_distance(header.sequence_number, expected_seq);
            if (diff > static_cast<int>(MAX_JITTER_PACKETS) ||
                (diff > 0 && jitter_buffer.size() >= MAX_JITTER_PACKETS &&
                 jitter_buffer.count(header.sequence_number) == 0)) {
                // Discard pending data and resynchronize, bounding both memory and latency.
                std::cerr << "[RTPClient] Jitter window exceeded; clearing buffer and resynchronizing\n";
                dropped_packets_count += static_cast<uint64_t>(diff);
                jitter_buffer.clear();
                expected_seq = header.sequence_number;
                missing_timer_active = false;
                diff = 0;
            }

            if (diff == 0) {
                // In-order packet: write immediately to output.bin
                out_file.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
                out_file.flush();
                if (!out_file) throw std::runtime_error("Failed to write output file");
                total_bytes_written += payload.size();
                expected_seq++;

                // Reset missing sequence timer
                missing_timer_active = false;

                // Flush any contiguous sequence numbers already waiting in jitter buffer
                flush_jitter_buffer(jitter_buffer, expected_seq, out_file,
                                    total_bytes_written, missing_timer_active,
                                    missing_seq_start_time);

                if (total_packets_received % 30 == 0 || total_packets_received == 1) {
                    std::cout << "[RTPClient] Processed Packet #" << total_packets_received
                              << " | Seq: " << header.sequence_number
                              << " | TS: " << header.timestamp
                              << " | Buffer Size: " << jitter_buffer.size() << std::endl;
                }
            } else if (diff > 0) {
                // Out-of-order future packet: buffer it
                std::cout << "[RTPClient] Out-of-order packet: Seq " << header.sequence_number
                          << " (expected " << expected_seq << "). Buffering." << std::endl;

                jitter_buffer[header.sequence_number] = std::move(payload);

                // Start 500ms timeout countdown for the missing expected_seq if not already active
                if (!missing_timer_active) {
                    missing_seq_start_time = std::chrono::steady_clock::now();
                    missing_timer_active = true;
                }
            } else {
                // Late or duplicate packet (sequence number precedes expected_seq)
                std::cerr << "[RTPClient] Discarding late/duplicate packet: Seq "
                          << header.sequence_number << " (current expected: "
                          << expected_seq << ")" << std::endl;
            }
        }

        out_file.close();
        if (!out_file) throw std::runtime_error("Failed to close output file");

        std::cout << "\n--------------------------------------------------------\n"
                  << "[RTPClient] Shutting down receive loop.\n"
                  << "  Total Packets Received: " << total_packets_received << "\n"
                  << "  Total Bytes Written:    " << total_bytes_written << "\n"
                  << "  Packets Dropped:        " << dropped_packets_count << "\n"
                  << "  Remaining In Buffer:    " << jitter_buffer.size() << "\n"
                  << "  Output Written to:      " << output_filepath << std::endl;
    }

private:
    /**
     * @brief Flushes contiguous packets starting at expected_seq from the jitter buffer.
     */
    void flush_jitter_buffer(std::map<uint16_t, std::vector<uint8_t>>& jitter_buffer,
                             uint16_t& expected_seq,
                             std::ofstream& out_file,
                             uint64_t& total_bytes_written,
                             bool& missing_timer_active,
                             std::chrono::steady_clock::time_point& missing_seq_start_time) {
        while (!jitter_buffer.empty()) {
            auto it = jitter_buffer.find(expected_seq);
            if (it != jitter_buffer.end()) {
                out_file.write(reinterpret_cast<const char*>(it->second.data()),
                               static_cast<std::streamsize>(it->second.size()));
                out_file.flush();
                if (!out_file) throw std::runtime_error("Failed to write output file");
                total_bytes_written += it->second.size();
                jitter_buffer.erase(it);
                expected_seq++;
                missing_timer_active = false;
            } else {
                // Gap encountered: start timer for this new missing expected_seq
                if (!missing_timer_active) {
                    missing_seq_start_time = std::chrono::steady_clock::now();
                    missing_timer_active = true;
                }
                break;
            }
        }
    }

    int socket_fd_{-1};
    int port_{5004};
};

int main(int argc, char* argv[]) {
    try {
        posix_utils::install_shutdown_handlers();

        int listen_port = 5004;
        std::string output_file = "output.bin";

        if (argc >= 2) {
            std::string arg1 = argv[1];
            if (arg1 == "-h" || arg1 == "--help") {
                std::cout << "Usage: " << argv[0] << " [listen_port] [output_file]\n"
                          << "  listen_port : UDP port to bind and listen on (default: 5004)\n"
                          << "  output_file : Destination filepath for reassembled stream (default: output.bin)\n";
                return 0;
            }
            listen_port = posix_utils::parse_port(arg1);
        }
        if (argc >= 3) {
            output_file = argv[2];
        }

        RTPClient client(listen_port);
        client.start_receive_loop(output_file);
    } catch (const std::exception& ex) {
        std::cerr << "[RTPClient] Fatal Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
