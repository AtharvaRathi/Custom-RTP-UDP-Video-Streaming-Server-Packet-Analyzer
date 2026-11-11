#!/usr/bin/env bash
# End-to-end loopback demo: 2 MiB at 1400 bytes/33 ms takes about 50 seconds.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
PORT=5004
MEDIA_FILE="fake_video_stream_2mb.bin"
OUTPUT_FILE="output_received_stream.bin"
SERVER_LOG="server.log"
CLIENT_LOG="client.log"
ANALYZER_LOG="analyzer.log"
if [ "$(uname -s)" = Darwin ]; then DEFAULT_IF=lo0; else DEFAULT_IF=lo; fi
LOOPBACK_IF="${1:-${DEFAULT_IF}}"
USE_SUDO=0
ANALYZER_PID=""
CLIENT_PID=""
SERVER_PID=""

# A trap cleans up on failure/interruption too. Normal completion stops and
# reaps the receivers explicitly before cmp reads the closed output file.
capture_kill() {
    if [ "${USE_SUDO}" -eq 1 ]; then sudo -n kill "$@"; else kill "$@"; fi
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [ -n "${SERVER_PID}" ]; then
        kill -INT "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    if [ -n "${CLIENT_PID}" ]; then
        kill -INT "${CLIENT_PID}" 2>/dev/null || true
        wait "${CLIENT_PID}" 2>/dev/null || true
    fi
    if [ -n "${ANALYZER_PID}" ]; then
        capture_kill -INT "${ANALYZER_PID}" 2>/dev/null || true
        wait "${ANALYZER_PID}" 2>/dev/null || true
    fi
    exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '[1/4] Building project\n'
if command -v ninja >/dev/null 2>&1; then
    cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
else
    cmake -B build -DCMAKE_BUILD_TYPE=Release
fi
cmake --build build
printf '[2/4] Generating 2 MiB payload\n'
dd if=/dev/urandom of="${MEDIA_FILE}" bs=1048576 count=2 2>/dev/null

if [ "$(id -u)" -ne 0 ]; then
    sudo -v
    USE_SUDO=1
fi
rm -f "${OUTPUT_FILE}" "${SERVER_LOG}" "${CLIENT_LOG}" "${ANALYZER_LOG}"
printf '[3/4] Starting analyzer and client on %s:%s\n' "${LOOPBACK_IF}" "${PORT}"
# sudo forwards SIGINT to its child; credentials were acquired above.
if [ "${USE_SUDO}" -eq 1 ]; then
    sudo -n ./build/telemetry_analyzer "${LOOPBACK_IF}" "${PORT}" >"${ANALYZER_LOG}" 2>&1 &
else
    ./build/telemetry_analyzer "${LOOPBACK_IF}" "${PORT}" >"${ANALYZER_LOG}" 2>&1 &
fi
ANALYZER_PID=$!
./build/rtp_client "${PORT}" "${OUTPUT_FILE}" >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!

# Wait for actual initialization instead of assuming fixed startup delays.
ready=0
for ((attempt=0; attempt<100; attempt++)); do
    if ! kill -0 "${CLIENT_PID}" 2>/dev/null || ! capture_kill -0 "${ANALYZER_PID}" 2>/dev/null; then
        echo 'Receiver or analyzer failed to start; inspect client.log and analyzer.log.' >&2
        exit 1
    fi
    if grep -q 'Listening for RTP stream' "${CLIENT_LOG}" && grep -q 'Monitoring RTP stream' "${ANALYZER_LOG}"; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "${ready}" -ne 1 ]; then echo 'Pipeline startup timed out.' >&2; exit 1; fi

printf 'Streaming for approximately 50 seconds; telemetry is in analyzer.log\n'
./build/rtp_server "${MEDIA_FILE}" 127.0.0.1 "${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
server_status=0
wait "${SERVER_PID}" || server_status=$?
SERVER_PID=""
if [ "${server_status}" -ne 0 ]; then
    echo 'Server failed; inspect server.log.' >&2
    exit "${server_status}"
fi
# Drain trailing loopback packets and the 500 ms reorder timeout.
sleep 1
kill -INT "${CLIENT_PID}"
client_status=0
wait "${CLIENT_PID}" || client_status=$?
CLIENT_PID=""
capture_kill -INT "${ANALYZER_PID}"
analyzer_status=0
wait "${ANALYZER_PID}" || analyzer_status=$?
ANALYZER_PID=""
if [ "${client_status}" -ne 0 ] || [ "${analyzer_status}" -ne 0 ]; then
    echo 'Client or analyzer failed; inspect their logs.' >&2
    exit 1
fi
printf '[4/4] Verifying reassembled file\n'
if cmp "${MEDIA_FILE}" "${OUTPUT_FILE}"; then
    echo 'PASS: output is byte-for-byte identical; all processes stopped.'
else
    echo 'FAIL: output differs; inspect logs for packet loss or rejected packets.' >&2
    exit 1
fi
