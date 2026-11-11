#!/usr/bin/env python3
"""Loopback and offline-capture regression tests; no capture privileges required."""
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

build = pathlib.Path(sys.argv[1]).resolve()


def rtp(seq, data=b'x', first=0x80, pt=96):
    return struct.pack('!BBHII', first, pt, seq, seq * 3000, 0x10203040) + data


def await_condition(condition, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError('Timed out waiting for pipeline')


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def receiver_case(root, name, packets, expected, diagnostics=()):
    port = free_port()
    output, log = root / (name + '.bin'), root / (name + '.log')
    with log.open('w') as stream:
        child = subprocess.Popen([str(build / 'rtp_client'), str(port), str(output)], stdout=stream, stderr=stream)
        try:
            await_condition(lambda: 'Listening for RTP stream' in log.read_text())
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for packet in packets:
                    sock.sendto(packet, ('127.0.0.1', port))
                    time.sleep(0.01)
            await_condition(lambda: output.exists() and output.read_bytes() == expected)
            child.send_signal(signal.SIGINT)
            assert child.wait(timeout=3) == 0
            assert output.read_bytes() == expected
            for diagnostic in diagnostics:
                assert diagnostic in log.read_text(), log.read_text()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


with tempfile.TemporaryDirectory(prefix='rtp-tests-') as directory:
    root = pathlib.Path(directory)
    # Invalid packets must not establish sequence state or contaminate output.
    extended = rtp(1, b'\0\0\0\1' + b'\xbe\xde\0\1' + b'ext!' + b'B' + b'\0\0\0\4', first=0xb1)
    receiver_case(root, 'validation', [b'bad', rtp(50, first=0x40), rtp(50, pt=97),
                  rtp(50, first=0x90), rtp(50, first=0xa0, data=b'\0'),
                  rtp(50, data=b'x' * 4000), rtp(0, b'A'), extended], b'AB',
                  ['invalid RTP', 'truncated UDP'])
    receiver_case(root, 'wrap', [rtp(65534, b'A'), rtp(0, b'C'), rtp(65535, b'B'), rtp(0, b'C')], b'ABC')
    # seq 2 stays pending; a distant packet discards it and resynchronizes.
    receiver_case(root, 'bound', [rtp(0, b'A'), rtp(2, b'B'), rtp(100, b'Z'), rtp(1, b'late')], b'AZ', ['Jitter window exceeded'])
    receiver_case(root, 'loss', [rtp(0, b'A'), rtp(2, b'C')], b'AC', ['Packet Dropped'])

    # Exercise the transmitter and receiver together with a short real file.
    port = free_port()
    source, output, log = root / 'source.bin', root / 'output.bin', root / 'client.log'
    source.write_bytes(bytes(range(256)) * 20)
    with log.open('w') as stream:
        child = subprocess.Popen([str(build / 'rtp_client'), str(port), str(output)], stdout=stream, stderr=stream)
        try:
            await_condition(lambda: 'Listening for RTP stream' in log.read_text())
            subprocess.run([str(build / 'rtp_server'), str(source), '127.0.0.1', str(port)], check=True, stdout=subprocess.DEVNULL, timeout=5)
            await_condition(lambda: output.read_bytes() == source.read_bytes())
            child.send_signal(signal.SIGTERM)
            assert child.wait(timeout=3) == 0
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    # Server SIGINT must stop streaming instead of running to EOF.
    source.write_bytes(b'x' * 140000)
    child = subprocess.Popen([str(build / 'rtp_server'), str(source), '127.0.0.1', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.1)
        child.send_signal(signal.SIGINT)
        assert child.wait(timeout=3) != 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()

    # Offline DLT_NULL captures validate IP/UDP/RTP bounds without sudo.
    def frame(data, udp_size=None, fragment=0):
        udp = struct.pack('!HHHH', 43210, 6123, udp_size if udp_size is not None else 8 + len(data), 0) + data
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, fragment, 64, 17, 0, b'\x7f\0\0\1', b'\x7f\0\0\1')
        return struct.pack('<I', 2) + ip + udp

    pcap = root / 'test.pcap'
    packets = [frame(rtp(0, b'OK')), frame(rtp(1, pt=97)), frame(rtp(1, first=0x40)),
               frame(rtp(1, first=0x90)), frame(rtp(1), udp_size=65535),
               frame(rtp(1), fragment=0x2000), frame(rtp(1))[:-1]]
    capture = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 0)
    for packet in packets:
        capture += struct.pack('<IIII', 1, 0, len(packet), len(packet)) + packet
    pcap.write_bytes(capture)
    for interface in ['lo0', 'lo', 'en0']:
        result = subprocess.run([str(build / 'telemetry_analyzer'), interface, '6123', '--file', str(pcap)], capture_output=True, text=True, check=True, timeout=3)
        assert 'Monitored UDP Port:    6123' in result.stdout
        assert 'Total Packets Captured:1' in result.stdout, result.stdout
        assert 'Total Payload Data:    2 bytes' in result.stdout
    for args in [['--file'], ['--unknown'], ['lo0', '0'], ['lo0', '65536'], ['lo0', '5004junk']]:
        result = subprocess.run([str(build / 'telemetry_analyzer'), *args], capture_output=True, timeout=3)
        assert result.returncode == 1
print('PASS: validation, truncation, reordering/wrap, bounded buffer, loss timeout, signals, transfer, offline capture and CLI')
