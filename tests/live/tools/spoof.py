"""Send packets with a forged source address: TCP SYNs to a port, or ICMP echo requests.

Runs inside a lab node, fed on stdin: docker exec -i <node> python3 - SRC DST tcp|icmp PORT COUNT < spoof.py
(PORT is ignored for icmp). An edge that checks source addresses must drop every one of them.
"""
import socket
import struct
import sys

src, dst, proto, port, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp_syn(seq: int) -> bytes:
    def header(csum):
        # ports, seq, ack, header length (5 words), flags = SYN only, window, checksum, urgent pointer
        return struct.pack("!HHIIBBHHH", 20000 + seq, port, seq, 0, 5 << 4, 0x02, 64240, csum, 0)
    # The TCP checksum covers a pseudo-header with both addresses, the forged source included.
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, 20)
    return header(checksum(pseudo + header(0)))


def icmp_echo(seq: int) -> bytes:
    def message(csum):
        return struct.pack("!BBHHH", 8, 0, csum, 0x5350, seq) + b"spoof"
    return message(checksum(message(0)))


number = socket.IPPROTO_TCP if proto == "tcp" else socket.IPPROTO_ICMP
# IPPROTO_RAW: we write the IP header too, so the source address is whatever we put in it.
# The kernel fills in the total length and the header checksum.
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
for seq in range(1, count + 1):
    payload = tcp_syn(seq) if proto == "tcp" else icmp_echo(seq)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), seq, 0, 64, number, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    raw.sendto(ip + payload, (dst, 0))
print(f"sent {count} {proto} from {src} to {dst}")
