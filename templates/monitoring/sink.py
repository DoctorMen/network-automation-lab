"""The NOC's pager, for the lab: Alertmanager's webhook receiver (decision 0018).

It keeps every notification Alertmanager POSTs, with the time it arrived, and returns them all on a GET,
so a test can tell when an alert was delivered, not only that Prometheus raised it. It listens on
127.0.0.1 only (port: the first argument), inside noc's network namespace, where Alertmanager runs.
Standard library only.
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RECEIVED = []


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        RECEIVED.append({"received": time.time(), "notification": body})
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        out = json.dumps(RECEIVED).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass  # the notifications are the record; no access log


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Sink).serve_forever()
