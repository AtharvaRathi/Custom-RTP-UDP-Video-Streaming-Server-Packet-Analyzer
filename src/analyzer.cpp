#include "rtp_header.hpp"
#include "posix_utils.hpp"
#include <poll.h>

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <csignal>

#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <cmath>
#include <cstring>
#include <stdexcept>

/**
 * @brief Passive Network Telemetry Analyzer using libpcap.
 *
 * Captures, dissects, and evaluates RFC 3550 RTP streams over UDP in real time,
 * computing Packet Loss %, Throughput (Mbps), and Interarrival Jitter (ms).
 */
class NetworkTelemetryAnalyzer {
public:
    /**
     * @brief Construct an analyzer targeting a network device and UDP port.
     */
    NetworkTelemetryAnalyzer(const std::string& device, int port, const std::string& offline_file = "")
        : device_(device), port_(port), offline_file_(offline_file) {}

    ~NetworkTelemetryAnalyzer() {
        close_pcap();
    }

    // Disable copy semantics
    NetworkTelemetryAnalyzer(const NetworkTelemetryAnalyzer&) = delete;
    NetworkTelemetryAnalyzer& operator=(const NetworkTelemetryAnalyzer&) = delete;

    /**
     * @brief Opens the network capture device, compiles the BPF filter, and initiates packet capture.
     */
    void start_monitoring() {
        char errbuf[PCAP_ERRBUF_SIZE];
        std::memset(errbuf, 0, sizeof(errbuf));

        if (!offline_file_.empty()) {
            std::cout << "[Analyzer] Opening offline capture file: " << offline_file_ << std::endl;
            pcap_handle_ = ::pcap_open_offline(offline_file_.c_str(), errbuf);
            if (!pcap_handle_) {
                throw std::runtime_error("pcap_open_offline() failed: " + std::string(errbuf));
            }
        } else {
            std::cout << "[Analyzer] Initializing live capture on interface: " << device_ << std::endl;
            // 65535 snaplen, promiscuous mode = 1, read timeout = 100ms
            pcap_handle_ = ::pcap_open_live(device_.c_str(), 65535, 1, 100, errbuf);
            if (!pcap_handle_) {
                throw std::runtime_error(
                    "pcap_open_live() failed on interface '" + device_ + "': " + std::string(errbuf) +
                    "\n  Note: Packet capture on raw interfaces typically requires elevated privileges (e.g. sudo)."
                );
            }
        }

        // The signal handler only sets a sig_atomic_t flag. Capture handles are
        // accessed and destroyed solely by this thread, eliminating teardown races.
        if (offline_file_.empty() && ::pcap_setnonblock(pcap_handle_, 1, errbuf) < 0) {
            throw std::runtime_error("pcap_setnonblock() failed: " + std::string(errbuf));
        }

        // 1. Inspect Data Link Layer Type (DLT)
        datalink_type_ = ::pcap_datalink(pcap_handle_);
        if (datalink_type_ == DLT_NULL) {
            link_hdr_len_ = 4; // BSD / macOS loopback header (4 octets)
            std::cout << "[Analyzer] Detected DLT_NULL (macOS/BSD loopback, 4-byte header)" << std::endl;
        } else if (datalink_type_ == DLT_EN10MB) {
            link_hdr_len_ = 14; // Standard Ethernet header (14 octets)
            std::cout << "[Analyzer] Detected DLT_EN10MB (Standard Ethernet, 14-byte header)" << std::endl;
        } else if (datalink_type_ == 108 /* DLT_LOOP */) {
            link_hdr_len_ = 4;
            std::cout << "[Analyzer] Detected DLT_LOOP (4-byte header)" << std::endl;
        } else if (datalink_type_ == 113 /* DLT_LINUX_SLL */) {
            link_hdr_len_ = 16;
            std::cout << "[Analyzer] Detected DLT_LINUX_SLL (Linux Cooked socket, 16-byte header)" << std::endl;
        } else {
            throw std::runtime_error("Unsupported datalink type: " + std::to_string(datalink_type_));
        }

        // 2. Compile and Apply BPF Filter
        struct bpf_program bpf;
        std::string filter_exp = "udp port " + std::to_string(port_);
        std::cout << "[Analyzer] Compiling and setting BPF filter: \"" << filter_exp << "\"" << std::endl;

        if (::pcap_compile(pcap_handle_, &bpf, filter_exp.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::string err = ::pcap_geterr(pcap_handle_);
            close_pcap();
            throw std::runtime_error("pcap_compile() failed for filter '" + filter_exp + "': " + err);
        }

        if (::pcap_setfilter(pcap_handle_, &bpf) == -1) {
            std::string err = ::pcap_geterr(pcap_handle_);
            ::pcap_freecode(&bpf);
            close_pcap();
            throw std::runtime_error("pcap_setfilter() failed: " + err);
        }
        ::pcap_freecode(&bpf);

        last_throughput_calc_time_ = std::chrono::steady_clock::now();

        std::cout << "[Analyzer] Monitoring RTP stream health (Press Ctrl+C to stop)...\n"
                  << "--------------------------------------------------------------------------------" << std::endl;

        // 3. Start packet capture loop
        while (posix_utils::running) {
            const int result = ::pcap_dispatch(pcap_handle_, 64, pcap_packet_callback,
                                               reinterpret_cast<u_char*>(this));
            if (result == PCAP_ERROR) {
                throw std::runtime_error("pcap_dispatch() failed: " + std::string(::pcap_geterr(pcap_handle_)));
            }
            if (result == PCAP_ERROR_BREAK || (result == 0 && !offline_file_.empty())) break;
            // Nonblocking capture plus a bounded wait also permits idle shutdown
            // on macOS, where pcap_breakloop does not necessarily wake a read.
            if (result == 0 && posix_utils::running) ::poll(nullptr, 0, 50);
        }

        // 4. Print final summary report upon loop termination
        print_final_summary();
    }

    /**
     * @brief Dissects an incoming packet and updates telemetry metrics.
     */
    void process_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        if (!pkthdr || !packet) {
            return;
        }

        // Validate packet has sufficient length for Data Link + IPv4 (min 20) + UDP (8) + RTP Header (12)
        const size_t min_packet_len = link_hdr_len_ + 20 + 8 + RTPHeader::FIXED_HEADER_SIZE;
        if (pkthdr->caplen < min_packet_len) {
            return;
        }

        // --- Step 1: Data Link Layer Dissection ---
        const uint8_t* ip_ptr = packet + link_hdr_len_;

        // --- Step 2: IPv4 Header Dissection ---
        uint8_t ip_ver = (ip_ptr[0] >> 4) & 0x0F;
        if (ip_ver != 4) {
            return; // Only process IPv4 datagrams
        }

        uint8_t ip_ihl = ip_ptr[0] & 0x0F;
        size_t ip_hdr_len = static_cast<size_t>(ip_ihl) * 4;
        if (ip_hdr_len < 20 || pkthdr->caplen < link_hdr_len_ + ip_hdr_len + 8 + RTPHeader::FIXED_HEADER_SIZE) {
            return;
        }

        const size_t ip_total_len = (static_cast<size_t>(ip_ptr[2]) << 8) | ip_ptr[3];
        const unsigned fragment = (static_cast<unsigned>(ip_ptr[6]) << 8) | ip_ptr[7];
        if (ip_total_len < ip_hdr_len + 8 + RTPHeader::FIXED_HEADER_SIZE ||
            ip_total_len > pkthdr->caplen - link_hdr_len_ || (fragment & 0x3fffU) != 0) {
            return; // Reject truncated or fragmented IPv4 datagrams.
        }
        uint8_t protocol = ip_ptr[9];
        if (protocol != IPPROTO_UDP) {
            return; // Must be UDP
        }

        // --- Step 3: UDP Header Dissection ---
        const uint8_t* udp_ptr = ip_ptr + ip_hdr_len;
        uint16_t src_port = static_cast<uint16_t>((udp_ptr[0] << 8) | udp_ptr[1]);
        uint16_t dst_port = static_cast<uint16_t>((udp_ptr[2] << 8) | udp_ptr[3]);

        // Verify port match
        if (dst_port != port_ && src_port != port_) {
            return;
        }

        // --- Step 4: RTP Header Dissection ---
        const uint8_t* rtp_ptr = udp_ptr + 8;
        const size_t udp_len = (static_cast<size_t>(udp_ptr[4]) << 8) | udp_ptr[5];
        if (udp_len < 8 + RTPHeader::FIXED_HEADER_SIZE || udp_len > ip_total_len - ip_hdr_len) {
            return;
        }

        const size_t rtp_len = udp_len - 8;
        RTPHeader rtp_hdr{};
        size_t payload_offset = 0;
        size_t payload_len = 0;
        if (!RTPHeader::parse_packet(rtp_ptr, rtp_len, rtp_hdr, payload_offset, payload_len)) {
            return;
        }


        // Update telemetry metrics
        update_metrics(pkthdr, rtp_hdr, payload_len);
    }

private:
    static void pcap_packet_callback(u_char* user_args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        auto* analyzer = reinterpret_cast<NetworkTelemetryAnalyzer*>(user_args);
        if (analyzer) {
            analyzer->process_packet(pkthdr, packet);
        }
    }

    void update_metrics(const struct pcap_pkthdr* pkthdr, const RTPHeader& rtp_hdr, size_t payload_len) {
        // 1. Packet Loss Tracking via RTP Sequence Numbers
        if (first_packet_) {
            first_packet_ = false;
            expected_seq_ = rtp_hdr.sequence_number;
            total_packets_received_ = 1;
            total_packets_lost_ = 0;
            expected_seq_++;
        } else {
            int gap = qualcomm_rtp::sequence_distance(rtp_hdr.sequence_number, expected_seq_);
            if (gap == 0) {
                total_packets_received_++;
                expected_seq_++;
            } else if (gap > 0) {
                // Gap detected: sequence numbers skipped
                total_packets_lost_ += static_cast<uint64_t>(gap);
                total_packets_received_++;
                expected_seq_ = static_cast<uint16_t>(rtp_hdr.sequence_number + 1);
            } else {
                // Out-of-order or duplicate packet arrived
                if (total_packets_lost_ > 0) {
                    total_packets_lost_--; // Correct previous loss assumption
                }
                total_packets_received_++;
            }
        }

        uint64_t total_expected = total_packets_received_ + total_packets_lost_;
        double loss_pct = (total_expected > 0)
            ? (static_cast<double>(total_packets_lost_) / static_cast<double>(total_expected) * 100.0)
            : 0.0;

        // 2. Throughput Calculation (Payload Bytes / Sec -> Mbps)
        total_payload_bytes_ += payload_len;
        window_payload_bytes_ += payload_len;

        auto now = std::chrono::steady_clock::now();
        double elapsed_sec = std::chrono::duration<double>(now - last_throughput_calc_time_).count();
        if (elapsed_sec >= 1.0) {
            current_throughput_mbps_ = (static_cast<double>(window_payload_bytes_) * 8.0) / (elapsed_sec * 1000000.0);
            window_payload_bytes_ = 0;
            last_throughput_calc_time_ = now;
        } else if (current_throughput_mbps_ == 0.0 && elapsed_sec > 0.05) {
            current_throughput_mbps_ = (static_cast<double>(window_payload_bytes_) * 8.0) / (elapsed_sec * 1000000.0);
        }

        // 3. Jitter Calculation (RFC 3550 Formula based on pcap_pkthdr arrival time)
        double arrival_sec = static_cast<double>(pkthdr->ts.tv_sec) +
                             static_cast<double>(pkthdr->ts.tv_usec) / 1000000.0;
        double rtp_sec = static_cast<double>(rtp_hdr.timestamp) / 90000.0; // 90kHz sampling clock

        if (total_packets_received_ > 1) {
            double d_transit = (arrival_sec - prev_arrival_sec_) - (rtp_sec - prev_rtp_sec_);
            double d_ms = std::abs(d_transit) * 1000.0;

            // Exponential filter: J(i) = J(i-1) + (|D(i-1, i)| - J(i-1)) / 16
            jitter_ms_ = jitter_ms_ + (d_ms - jitter_ms_) / 16.0;
        }

        prev_arrival_sec_ = arrival_sec;
        prev_rtp_sec_     = rtp_sec;

        last_seq_  = rtp_hdr.sequence_number;
        last_ssrc_ = rtp_hdr.ssrc;
        last_ts_   = rtp_hdr.timestamp;

        // 4. Overwrite live dashboard line in terminal using \r
        print_live_dashboard(loss_pct);
    }

    void print_live_dashboard(double loss_pct) {
        std::cout << "\r\033[K[RTP Telemetry] "
                  << "Pkts: " << total_packets_received_
                  << " | Loss: " << std::fixed << std::setprecision(2) << loss_pct << "% (" << total_packets_lost_ << " lost)"
                  << " | Throughput: " << std::setprecision(3) << current_throughput_mbps_ << " Mbps"
                  << " | Jitter: " << std::setprecision(2) << jitter_ms_ << " ms"
                  << " | SSRC: 0x" << std::hex << std::uppercase << last_ssrc_ << std::dec
                  << " | Seq: " << last_seq_
                  << "   " << std::flush;
    }

    void print_final_summary() {
        uint64_t total_expected = total_packets_received_ + total_packets_lost_;
        double loss_pct = (total_expected > 0)
            ? (static_cast<double>(total_packets_lost_) / static_cast<double>(total_expected) * 100.0)
            : 0.0;

        std::cout << "\n\n=======================================================\n";
        std::cout << "          RTP STREAM TELEMETRY SUMMARY REPORT          \n";
        std::cout << "=======================================================\n";
        std::cout << "  Interface / Source:    " << (offline_file_.empty() ? device_ : offline_file_) << "\n";
        std::cout << "  Monitored UDP Port:    " << port_ << "\n";
        std::cout << "  Total Packets Captured:" << total_packets_received_ << "\n";
        std::cout << "  Total Packets Lost:    " << total_packets_lost_ << "\n";
        std::cout << "  Final Packet Loss Rate:" << std::fixed << std::setprecision(2) << loss_pct << "%\n";
        std::cout << "  Total Payload Data:    " << total_payload_bytes_ << " bytes ("
                  << std::setprecision(2) << (static_cast<double>(total_payload_bytes_) / 1048576.0) << " MB)\n";
        std::cout << "  Average Throughput:    " << std::setprecision(3) << current_throughput_mbps_ << " Mbps\n";
        std::cout << "  Interarrival Jitter:   " << std::setprecision(2) << jitter_ms_ << " ms\n";
        std::cout << "  Last Stream SSRC:      0x" << std::hex << std::uppercase << last_ssrc_ << std::dec << "\n";
        std::cout << "  Last Sequence Number:  " << last_seq_ << "\n";
        std::cout << "=======================================================\n";
    }

    void close_pcap() {
        if (pcap_handle_) {
            ::pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
        }
    }

    std::string device_;
    int port_{5004};
    std::string offline_file_;
    pcap_t* pcap_handle_{nullptr};
    int datalink_type_{0};
    size_t link_hdr_len_{0};

    // Telemetry state
    bool first_packet_{true};
    uint16_t expected_seq_{0};
    uint64_t total_packets_received_{0};
    uint64_t total_packets_lost_{0};
    uint64_t total_payload_bytes_{0};

    // Throughput state
    uint64_t window_payload_bytes_{0};
    std::chrono::steady_clock::time_point last_throughput_calc_time_;
    double current_throughput_mbps_{0.0};

    // RFC 3550 Jitter State
    double prev_arrival_sec_{0.0};
    double prev_rtp_sec_{0.0};
    double jitter_ms_{0.0};

    uint32_t last_ssrc_{0};
    uint16_t last_seq_{0};
    uint32_t last_ts_{0};
};

int main(int argc, char* argv[]) {

    // Determine default loopback interface according to OS platform
    std::string device;
#if defined(__APPLE__)
    device = "lo0";
#else
    device = "lo";
#endif

    int port = 5004;
    std::string offline_file;
    int positional_count = 0;

    try {
        posix_utils::install_shutdown_handlers();
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-h" || arg == "--help") {
                std::cout << "Usage: " << argv[0] << " [options] [interface] [port]\n"
                          << "  interface       : Network interface name (default: lo0 on macOS, lo on Linux)\n"
                          << "  port            : Target UDP port (default: 5004)\n"
                          << "Options:\n"
                          << "  --file <pcap>   : Analyze an offline pcap capture file\n"
                          << "  -h, --help      : Display this help message\n";
                return 0;
            } else if (arg == "--file") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--file requires a capture file path");
                }
                offline_file = argv[++i];
            } else if (!arg.empty() && arg[0] == '-') {
                throw std::invalid_argument("Unknown option: " + arg);
            } else {
                // Track position explicitly: the interface may equal the default.
                if (positional_count == 0) {
                    device = arg;
                } else if (positional_count == 1) {
                    port = posix_utils::parse_port(arg);
                } else {
                    throw std::invalid_argument("Too many positional arguments; expected [interface] [port]");
                }
                ++positional_count;
            }
        }

        NetworkTelemetryAnalyzer analyzer(device, port, offline_file);
        analyzer.start_monitoring();
    } catch (const std::exception& ex) {
        std::cerr << "[Analyzer] Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
