"""Command accounting for FRR on a router we own (OROS ACC-1, ACC-2; decision 0029).

FRR's own vty sockets (/var/run/frr/<daemon>.vty) are open only to root and the frrvty group, and no
person or tool is in that group. Everyone else reaches FRR through this proxy: one socket per daemon in
the folder given as the second argument, which vtysh uses with --vty_socket (the /usr/local/bin/vtysh shim adds it for every account but
root). For each connection the kernel says which uid made it (SO_PEERCRED: a process can't set that, the
way it can set $USER), and the proxy then:

- refuses an account outside the admin group (the first argument), and logs `refuse`;
- otherwise logs `accept`, connects to the daemon's own socket and relays both ways, logging every command
  vtysh sends (`command`) on one line, with each secret replaced by <hidden>.

Each line goes to syslog (facility authpriv), where busybox syslogd keeps the box's copy, and straight to
the NOC's collector (the third argument, or - for none) from a UDP port below 1024 (the fourth). No other
account can send from such a port (the routers set net.ipv4.ip_unprivileged_port_start to 1024), and the
collector takes as a record only what comes from it: a line another account writes to syslog, or sends to
the collector itself, stays an ordinary syslog line. Root on the router can still use FRR's own sockets,
stop this proxy or delete the box's copy, but not reach what already left (RISK-60). Standard library only;
runs as root.
"""
import grp
import os
import pwd
import re
import socket
import struct
import sys
import syslog
import threading
import time
from datetime import datetime

FRR = "/var/run/frr"
# vtysh sends each command as one string ending in a NUL byte, and a daemon ends each answer with three
# NUL bytes and its return code (FRR lib/vty.c); 1 is CMD_WARNING.
END = b"\0"
WARNING = b"\0\0\0\1"
# The keywords FRR 8.4 takes a secret after, in the daemons these routers run: `neighbor X password`,
# `key-string`, `ip ospf authentication-key` and `ip ospf message-digest-key N md5` (and `ip rip authentication
# string`, whose `authentication` starts authentication-key). FRR takes any unambiguous start of a keyword
# (`passw`), so any word that starts one of them hides the rest of its command, and so does any word with password
# in it (isisd's area-password and domain-password, were it ever started). A word that does so by chance (a
# route-map named m) costs that record its detail, never a secret.
SECRET_WORDS = ("password", "key-string", "authentication-key", "md5")


def daemons() -> list[str]:
    """The daemons this router's daemons file starts, and watchfrr, which vtysh also talks to."""
    with open("/etc/frr/daemons") as f:
        started = re.findall(r"^(zebra|\w+d)=yes", f.read(), re.M)
    return [*started, "watchfrr"]


def who(conn: socket.socket) -> tuple[int, int, str]:
    pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    try:
        return pid, uid, pwd.getpwuid(uid).pw_name
    except KeyError:
        return pid, uid, str(uid)  # a uid with no account at all


def allowed(uid: int) -> bool:
    """Read at every connection, so an account added to the group by hand counts at once."""
    if uid == 0:
        return True
    try:
        group, account = grp.getgrnam(GROUP), pwd.getpwuid(uid)
    except KeyError:
        return False
    return account.pw_name in group.gr_mem or account.pw_gid == group.gr_gid


def record(command: bytes) -> str:
    """A command as its record holds it: on one line, with whatever follows a secret keyword replaced by <hidden>
    and any other control character written as \\xNN, so no command can put a line of its own in the log."""
    words = command.decode(errors="replace").split()
    for i, w in enumerate(words[:-1]):
        if any(s.startswith(w.lower()) for s in SECRET_WORDS) or "password" in w.lower():
            words = words[:i + 1] + ["<hidden>"]
            break
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in " ".join(words))


def send(message: str) -> None:
    """One record to the collector from this proxy's own port, framed as busybox syslogd frames what it sends
    on (authpriv.info). A record that can't leave now (no route to the NOC yet) stays only in the box's copy."""
    now = datetime.now()
    try:
        OUT.sendto(f"<86>{now:%b} {now.day:2d} {now:%H:%M:%S} vty-aaa[{os.getpid()}]: {message}".encode(), COLLECTOR)
    except OSError:
        pass


def log(event: str, user: str, uid: int, daemon: str, pid: int, extra: str = "") -> None:
    message = f"{event} user={user} uid={uid} daemon={daemon} pid={pid}{extra}"
    syslog.syslog(syslog.LOG_INFO, message)
    if COLLECTOR:
        send(message)


def relay(src: socket.socket, dst: socket.socket, account=None) -> None:
    """Copy src to dst until src closes. With account, log each complete command on the way."""
    pending = b""
    try:
        while data := src.recv(65536):
            if account:
                pending += data
                *commands, pending = pending.split(END)
                for c in commands:
                    account(record(c))
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def refuse(conn: socket.socket) -> None:
    """Answer every command with an error, the way a daemon answers one it rejects. Closing the socket instead
    would make vtysh reconnect again and again."""
    pending = b""
    try:
        while data := conn.recv(65536):
            pending += data
            *commands, pending = pending.split(END)
            for _ in commands:
                conn.sendall(f"% only the {GROUP} group may use FRR here\n".encode() + WARNING)
    except OSError:
        pass
    conn.close()


def session(conn: socket.socket, daemon: str) -> None:
    pid, uid, user = who(conn)
    if not allowed(uid):
        log("refuse", user, uid, daemon, pid, f" reason=not-in-{GROUP}")
        refuse(conn)
        return
    upstream = socket.socket(socket.AF_UNIX)
    try:
        upstream.connect(f"{FRR}/{daemon}.vty")
    except OSError:
        conn.close()  # the daemon isn't running: vtysh sees it as down, as it would without the proxy
        return
    log("accept", user, uid, daemon, pid)
    threading.Thread(target=relay, args=(upstream, conn), daemon=True).start()
    relay(conn, upstream, lambda line: log("command", user, uid, daemon, pid, f" line={line}"))


def alive(daemon: str) -> bool:
    probe = socket.socket(socket.AF_UNIX)
    try:
        probe.connect(f"{FRR}/{daemon}.vty")
        return True
    except OSError:
        return False
    finally:
        probe.close()


def listen(daemon: str) -> socket.socket:
    path = f"{SOCKETS}/{daemon}.vty"
    if os.path.exists(path):
        os.unlink(path)
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(path)
    os.chmod(path, 0o666)  # anyone may try: a refused attempt is logged, not lost to a permission error
    listener.listen(64)

    def accept():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return  # closed: the daemon stopped
            threading.Thread(target=session, args=(conn, daemon), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    return listener


def watch(names: list[str]) -> None:
    """Offer a daemon's socket only while the daemon answers on its own. vtysh then sees a daemon that is
    starting or has stopped as not running, as it would without the proxy; a socket that accepts and then
    finds nothing behind it makes vtysh retry and print I/O errors instead."""
    listeners = {}
    while True:
        for d in names:
            up = alive(d)
            if up and d not in listeners:
                listeners[d] = listen(d)
            elif not up and d in listeners:
                os.unlink(f"{SOCKETS}/{d}.vty")
                listener = listeners.pop(d)
                listener.shutdown(socket.SHUT_RDWR)  # wakes the accept() waiting in its thread
                listener.close()
        time.sleep(1)


COLLECTOR = None  # (address, port) of the NOC's collector, or None where the NOC collects nothing
OUT = None

if __name__ == "__main__":
    GROUP, SOCKETS, to, own_port = sys.argv[1:5]
    syslog.openlog("vty-aaa", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    if to != "-":
        address, port = to.rsplit(":", 1)
        COLLECTOR = (address, int(port))
        OUT = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        OUT.bind(("", int(own_port)))
    os.makedirs(SOCKETS, mode=0o755, exist_ok=True)
    for stale in os.listdir(SOCKETS):  # left by an earlier run of this proxy
        os.unlink(f"{SOCKETS}/{stale}")
    watch(daemons())
