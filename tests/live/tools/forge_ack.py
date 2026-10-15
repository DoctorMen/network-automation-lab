"""Send one TCP packet with only ACK set, as if from the middle of a connection that never opened.

Runs inside a lab node, fed on stdin: docker exec -i <node> python3 - DST DPORT SPORT < forge_ack.py
A stateful firewall has seen no handshake for it, so it must not forward it.
"""
import socket
import struct
import sys

dst, dport, sport = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])


def checksum(data: bytes) -> int:
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp_header(csum: int) -> bytes:
    # ports, seq, ack, header length (5 words), flags = ACK only, window, checksum, urgent pointer
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, 0x10, 64240, csum, 0)


# The TCP checksum covers a pseudo-header with both addresses, so find the source the kernel will use.
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
probe.connect((dst, dport))
src = probe.getsockname()[0]
pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, 20)

# SOCK_RAW with IPPROTO_TCP: we write the TCP header, the kernel adds the IP header.
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
raw.sendto(tcp_header(checksum(pseudo + tcp_header(0))), (dst, 0))
print(f"forged ACK {src}:{sport} -> {dst}:{dport}")
