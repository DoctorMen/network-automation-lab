"""TCP connect scan of every address and port at once (what nmap -sT does), from one source address.

Runs inside a lab node, fed on stdin: docker exec -i <node> python3 - SRC TIMEOUT TARGETS < scan.py
TARGETS is a JSON list of [address, port]; SRC 0.0.0.0 lets the kernel pick. Prints JSON:
{"address:port": "open" | "closed" | "filtered"}. Open: the handshake completed. Closed: a reset
came back. Filtered: nothing came back before TIMEOUT, which is what a DROP rule looks like.
All connects start together, so a scan takes TIMEOUT seconds however many ports are filtered;
one at a time, busybox nc would wait its full -w on every filtered port.
"""
import errno
import json
import selectors
import socket
import sys
import time

src, timeout, targets = sys.argv[1], float(sys.argv[2]), json.loads(sys.argv[3])

sel = selectors.DefaultSelector()
result = {}
for address, port in targets:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    s.bind((src, 0))
    rc = s.connect_ex((address, port))
    if rc not in (0, errno.EINPROGRESS):
        result[f"{address}:{port}"] = "closed"
        s.close()
        continue
    sel.register(s, selectors.EVENT_WRITE, f"{address}:{port}")

deadline = time.monotonic() + timeout
while sel.get_map() and time.monotonic() < deadline:
    for key, _ in sel.select(max(0.0, deadline - time.monotonic())):
        # Writable means the connect finished; SO_ERROR says how.
        err = key.fileobj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        result[key.data] = "open" if err == 0 else "closed"
        sel.unregister(key.fileobj)
        key.fileobj.close()
for key in list(sel.get_map().values()):
    result[key.data] = "filtered"
    key.fileobj.close()
print(json.dumps(result))
