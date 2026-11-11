#ifndef POSIX_UTILS_HPP
#define POSIX_UTILS_HPP
#include <signal.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

namespace posix_utils {
inline volatile sig_atomic_t running = 1;
inline void stop_handler(int) { running = 0; }
inline void install_shutdown_handlers() {
    struct sigaction action{};
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGINT);
    sigaddset(&action.sa_mask, SIGTERM);
    action.sa_flags = 0; // Do not restart interrupted syscalls.
    if (sigaction(SIGINT, &action, nullptr) < 0 || sigaction(SIGTERM, &action, nullptr) < 0) {
        throw std::runtime_error(std::string("sigaction failed: ") + std::strerror(errno));
    }
}
inline int parse_port(const std::string& text) {
    if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
        throw std::invalid_argument("Port must be an integer in the range 1-65535");
    const int port = std::stoi(text);
    if (port < 1 || port > 65535) throw std::invalid_argument("Port must be in the range 1-65535");
    return port;
}
}
#endif
