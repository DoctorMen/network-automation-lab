"""The far end of an abuse complaint: a server on the internet that notes who connected to it, and when.

Runs inside a lab node, fed on stdin: docker exec -i <node> python3 - ADDRESS PORT COUNT TIMEOUT < complaint.py
Listens on ADDRESS:PORT, prints "listening" once it does, then for each of up to COUNT connections one line,
"PEER_ADDRESS PEER_PORT UNIX_TIME": the address and port the connection came from, as this end saw them,
which is all a complaint from outside can give. Stops after COUNT connections, or TIMEOUT seconds.
"""
import socket
import sys
import time

address, port, count, timeout = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((address, port))
server.listen(count)
print("listening", flush=True)
deadline = time.time() + timeout
for _ in range(count):
    server.settimeout(max(deadline - time.time(), 0.1))
    try:
        conn, (peer, peer_port) = server.accept()
    except socket.timeout:
        break
    print(peer, peer_port, time.time(), flush=True)
    conn.close()
