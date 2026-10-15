"""Capture IPv4 ICMP on one interface, as a pcap on stdout: python3 capture.py IFACE SECONDS

The router image has no tcpdump, and installing one would change the device under test, so
`netlab finding` runs this with the image's own Python. It is the capture filter `icmp` in about
twenty lines: an AF_PACKET socket sees every frame the interface sends or receives, and only IPv4
frames carrying ICMP (protocol 1) are kept. Timestamps are taken when Python reads the frame, so
they are good to about a millisecond, not to the microsecond a kernel timestamp would be."""
import socket
import struct
import sys
import time

SNAPLEN = 256  # headers and the start of the payload; enough to read every ICMP type, id and sequence

iface, seconds = sys.argv[1], float(sys.argv[2])
out = sys.stdout.buffer
# pcap file header (tcpdump.org/manpages/pcap-savefile.5.txt): magic, version 2.4, UTC, snaplen, Ethernet
out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 1))
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL: in and out
sock.bind((iface, 0))
deadline = time.time() + seconds
while time.time() < deadline:
    sock.settimeout(max(deadline - time.time(), 0.01))
    try:
        frame = sock.recv(65535)
    except socket.timeout:
        break
    if frame[12:14] == b"\x08\x00" and frame[23] == 1:  # EtherType IPv4, IP protocol ICMP
        now = time.time()
        kept = frame[:SNAPLEN]
        out.write(struct.pack("<IIII", int(now), int(now % 1 * 1e6), len(kept), len(frame)) + kept)
