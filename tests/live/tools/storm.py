"""Broadcast storm source for tests/live/test_storm.py: python3 - IFACE PPS SECONDS.

Sends broadcast ARP requests from IFACE at about PPS frames a second for SECONDS, in bursts of a hundredth
of a second, and prints how many it sent. Capped by PPS on purpose: an unthrottled sender reached about
400k frames a second here and would starve OSPF, BGP and the other tests of CPU on a shared runner."""
import socket
import sys
import time

iface, pps, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
src = s.getsockname()[4]
# Ethernet broadcast, ARP, "who has 10.10.10.12" from an address no host answers: a real storm's usual frame.
frame = (b"\xff" * 6 + src + b"\x08\x06" + b"\x00\x01\x08\x00\x06\x04\x00\x01" + src + b"\x0a\x0a\x0a\x0c"
         + b"\x00" * 6 + b"\x0a\x0a\x0a\x01" + b"\x00" * 18)
batch = max(1, pps // 100)
end = time.time() + seconds
sent = 0
while time.time() < end:
    started = time.time()
    for _ in range(batch):
        s.send(frame)
        sent += 1
    left = 0.01 - (time.time() - started)
    if left > 0:
        time.sleep(left)
print(sent)
