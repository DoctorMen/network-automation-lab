"""UDP traffic of a known size, for tests/live/observe/test_loss.py. Fed to `python3 -` on a node, it needs
nothing but the node's Python.

send ADDRESS PORT COUNT SIZE SOCKETS   COUNT datagrams of SIZE bytes as fast as SOCKETS sockets take them,
                                       one after the other on each: a microburst. One socket can't
                                       overflow a queue of 1000 packets, because its own send buffer
                                       holds far fewer datagrams and blocks it first.
pace ADDRESS PORT COUNT SIZE RATE      COUNT datagrams of SIZE bytes from one socket, RATE a second.
recv PORT IDLE                         counts what arrives on PORT until IDLE seconds pass with nothing.
                                       Prints "listening" once it is, then the counts at the end.

Each prints one JSON line at the end. A sender's `sent` counts every datagram send() accepted: a
datagram the node's own queue then drops still counts as sent (V-025).
"""
import json
import socket
import sys
import time


def send(address, port, count, size, sockets):
    socks = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(sockets)]
    payload = b"x" * size
    started = time.monotonic()
    for i in range(count):
        socks[i % sockets].sendto(payload, (address, port))
    print(json.dumps({"sent": count, "seconds": round(time.monotonic() - started, 4)}))


def pace(address, port, count, size, rate):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"x" * size
    started = time.monotonic()
    for i in range(count):
        wait = started + i / rate - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        s.sendto(payload, (address, port))
    print(json.dumps({"sent": count, "seconds": round(time.monotonic() - started, 4)}))


def recv(port, idle):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # A large buffer (privileged: SO_RCVBUFFORCE), so the receiver itself drops nothing of a burst.
    s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_RCVBUFFORCE", 33), 32 * 1024 * 1024)
    s.bind(("0.0.0.0", port))
    print("listening", flush=True)
    s.settimeout(idle)
    received = size = 0
    while True:
        try:
            data = s.recv(65535)
        except socket.timeout:
            break
        received += 1
        size += len(data)
    print(json.dumps({"received": received, "bytes": size}), flush=True)


if __name__ == "__main__":
    cmd, *args = sys.argv[1:]
    if cmd == "send":
        send(args[0], int(args[1]), int(args[2]), int(args[3]), int(args[4]))
    elif cmd == "pace":
        pace(args[0], int(args[1]), int(args[2]), int(args[3]), float(args[4]))
    else:
        recv(int(args[0]), float(args[1]))
