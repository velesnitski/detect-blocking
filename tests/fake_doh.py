#!/usr/bin/env python3
"""Fake DoH server fixture for tests/test_doh_compromise.sh.

Returns deterministic sinkhole-style answers (8.47.69.0 / 8.6.112.0) for
ANY DoH query, including the integrity-check canary (one.one.one.one).
The script under test should detect this mismatch and emit the
"DoH path is compromised" verdict.

The 8.0.0.0/8 sinkhole pattern is a publicly known DPI behaviour;
no internal data is referenced.

Usage: python3 fake_doh.py [PORT]   # default port 58880
"""
import http.server
import json
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 58880

BODY = json.dumps({
    "Status": 0,
    "TC": False, "RD": True, "RA": True, "AD": False, "CD": False,
    "Question": [{"name": "x", "type": 1}],
    "Answer": [
        {"name": "x", "type": 1, "TTL": 60, "data": "8.47.69.0"},
        {"name": "x", "type": 1, "TTL": 60, "data": "8.6.112.0"},
    ],
}).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    print(f"fake_doh: listening on 127.0.0.1:{PORT}", flush=True)
    http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
