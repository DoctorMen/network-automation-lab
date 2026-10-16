"""Time a series of small web requests, as a user would see them.

Runs inside a lab node, fed on stdin:
  docker exec -i <client> python3 - URL COUNT INTERVAL < web_latency.py
Prints one JSON object: the time of every request in milliseconds, and how many failed. A failed
request has no time, so the caller must count it as over any target, never leave it out.
"""
import json
import sys
import time
import urllib.request

url, count, interval = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
times, failed = [], 0
for _ in range(count):
    start = time.monotonic()
    try:
        urllib.request.urlopen(url, timeout=5).read()
        times.append(round((time.monotonic() - start) * 1000, 2))
    except OSError:
        failed += 1
    time.sleep(interval)
print(json.dumps({"ms": times, "failed": failed}))
