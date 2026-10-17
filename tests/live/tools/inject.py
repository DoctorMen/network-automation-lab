"""Try to slip a second record into the accounting proxy's log through the proxy itself.

Runs as root inside a router we own, fed on stdin: docker exec -i <router> python3 - UID SOCKET TEXT < inject.py
Drops to UID first, so the proxy sees that account (SO_PEERCRED), then sends one command the way vtysh frames
it (ending in a NUL byte) whose text holds a newline followed by TEXT, a line made to look like a record of its
own. Prints the daemon's answer.
"""
import os
import pwd
import socket
import sys

uid, path, text = int(sys.argv[1]), sys.argv[2], sys.argv[3]
os.setgroups([])
os.setgid(pwd.getpwuid(uid).pw_gid)
os.setuid(uid)
conn = socket.socket(socket.AF_UNIX)
conn.settimeout(5)
conn.connect(path)
conn.sendall(b"show version\n" + text.encode() + b"\0")
answer = b""
try:
    while answer[-4:-1] != b"\0\0\0":  # a daemon ends its answer with three NUL bytes and a return code
        chunk = conn.recv(65536)
        if not chunk:
            break
        answer += chunk
except socket.timeout:
    pass
conn.close()
print(answer.decode(errors="replace"))
