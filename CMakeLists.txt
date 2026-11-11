cmake_minimum_required(VERSION 3.16)

# Project Definition
project(qualcomm_rtp_streamer
    VERSION 1.0.0
    DESCRIPTION "High-performance POSIX RTP/UDP streaming server and libpcap network telemetry analyzer"
    LANGUAGES C CXX
)

# Enforce C++17 Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDE tooling (clangd, compile_commands.json)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Strict compiler warnings for mission-critical systems programming
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wformat=2
        -Wundef
        -Werror=return-type
    )
endif()

# ==============================================================================
# Dependency 1: POSIX Threads (pthread)
# ==============================================================================
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ==============================================================================
# Dependency 2: libpcap (Cross-Platform: Linux & macOS Apple Silicon / Intel)
# ==============================================================================
# Optional pkg-config lookup
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PCAP_PKG QUIET libpcap)
endif()

# Robust path discovery for header files across macOS (Apple Silicon / Intel) and Linux
find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h
    HINTS ${PCAP_PKG_INCLUDE_DIRS}
    PATHS
        /opt/homebrew/include
        /opt/homebrew/opt/libpcap/include
        /usr/local/include
        /usr/include
)

# Robust path discovery for shared/static library
find_library(PCAP_LIBRARY
    NAMES pcap
    HINTS ${PCAP_PKG_LIBRARY_DIRS}
    PATHS
        /opt/homebrew/lib
        /opt/homebrew/opt/libpcap/lib
        /usr/local/lib
        /usr/lib
        /usr/lib/x86_64-linux-gnu
        /usr/lib/aarch64-linux-gnu
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
    REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR
    FAIL_MESSAGE "libpcap was not found. Please install libpcap development headers:
  - Debian/Ubuntu: sudo apt-get install libpcap-dev
  - macOS: brew install libpcap"
)

# Register imported target for libpcap
if(PCAP_FOUND AND NOT TARGET pcap::pcap)
    add_library(pcap::pcap UNKNOWN IMPORTED)
    set_target_properties(pcap::pcap PROPERTIES
        IMPORTED_LOCATION "${PCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
    )
endif()

# Global Include Directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# ==============================================================================
# Core Library Target: rtp_core
# ==============================================================================
add_library(rtp_core INTERFACE)
target_include_directories(rtp_core INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(rtp_core INTERFACE
    Threads::Threads
    pcap::pcap
)

# ==============================================================================
# Executables
# ==============================================================================
# RTP Video Streaming Server
add_executable(rtp_server src/server.cpp)
target_link_libraries(rtp_server PRIVATE rtp_core)

# RTP Video Streaming Client
add_executable(rtp_client src/client.cpp)
target_link_libraries(rtp_client PRIVATE rtp_core)

# RTP Network Telemetry Analyzer (libpcap)
add_executable(telemetry_analyzer src/analyzer.cpp)
target_link_libraries(telemetry_analyzer PRIVATE rtp_core)

# ==============================================================================
# Verification & Test Executable
# ==============================================================================
option(BUILD_TESTS "Build RFC 3550 RTP verification test suite" ON)

if(BUILD_TESTS)
    enable_testing()
    add_executable(test_rtp_header tests/test_rtp_header.cpp)
    target_link_libraries(test_rtp_header PRIVATE rtp_core)
    add_test(NAME test_rtp_header COMMAND test_rtp_header)
endif()

# Integration tests use only Python's standard library and unprivileged loopback.
if(BUILD_TESTS)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME test_pipeline
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_pipeline.py
                    $<TARGET_FILE_DIR:rtp_client>)
        set_tests_properties(test_pipeline PROPERTIES TIMEOUT 30)
    endif()
endif()
