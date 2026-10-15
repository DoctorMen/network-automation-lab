"""Stand-in for a nightly backup: one TCP stream of a fixed size to an off-site receiver.

Runs inside a lab node, fed on stdin:
  docker exec -i <receiver> python3 - recv PORT < backup.py           prints the bytes received
  docker exec -i <sender> python3 - send HOST PORT BYTES < backup.py  prints the bytes sent
The copy itself has no rate limit. Anything that slows it down is applied from outside, by the
sender's queueing (tc), which is the point of the test.
"""
import socket
import sys
import time

if sys.argv[1] == "recv":
    server = socket.create_server(("0.0.0.0", int(sys.argv[2])))
    server.settimeout(120)  # never hang a test run if the sender doesn't come
    conn, _ = server.accept()
    received = 0
    while chunk := conn.recv(65536):
        received += len(chunk)
    print(received)  # counted before anything is cleaned up: the receiver's own tally
else:
    host, port, size = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    for _ in range(50):  # the receiver may still be starting
        try:
            sock = socket.create_connection((host, port), timeout=5)
            break
        except OSError:
            time.sleep(0.1)
    block, sent = bytes(65536), 0
    while sent < size:
        sock.sendall(block[:min(len(block), size - sent)])
        sent += min(len(block), size - sent)
    sock.shutdown(socket.SHUT_WR)
    sock.recv(1)  # wait until the receiver has read everything and closed
    print(sent)
