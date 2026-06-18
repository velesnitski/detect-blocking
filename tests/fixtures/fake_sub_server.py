#!/usr/bin/env python3
"""Hermetic subscription endpoint for tests — no real infra.

Mimics the awkward bits of a real panel so the tool's fetch path is exercised
end to end:
  * UA-gated: a request without the client User-Agent gets 403.
  * one-shot 302 cookie challenge: the first (UA-OK) request is redirected to
    itself with a Set-Cookie; only the cookied follow-up gets the body.
  * body: a JSON array of Xray configs built from SAFE placeholders (all-zero
    UUID, all-'A' pubkey, www.example.com cover) pointing at loopback CLOSED
    ports, so the fleet walk's TCP precheck fast-fails to "unreachable" — fast
    and deterministic, no outbound network.

Binds 127.0.0.1 on an ephemeral port and prints `PORT=<n>` (flushed) on stdout
so the test can read it, then serves forever until killed.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

ALLOWED_UA = "Happ"  # the tool defaults to Happ/2.6.0; gate on a substring
PBK = "A" * 43
UUID = "00000000-0000-0000-0000-000000000000"


def _vless(remarks, port):
    return {
        "remarks": remarks,
        "outbounds": [{
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1", "port": port,
                "users": [{"id": UUID, "flow": "xtls-rprx-vision", "encryption": "none"}],
            }]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "publicKey": PBK, "serverName": "www.example.com",
                "shortId": "01", "fingerprint": "chrome"}},
        }],
    }


SUB = [
    _vless("Alpha", 1),
    _vless("Bravo", 2),
    {"remarks": "Charlie Hysteria", "outbounds": [{"protocol": "freedom"}]},
]
BODY = json.dumps(SUB).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):  # keep test output clean
        pass

    def do_GET(self):
        if ALLOWED_UA not in (self.headers.get("User-Agent") or ""):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"forbidden: client UA required")
            return
        if "chal=ok" not in (self.headers.get("Cookie") or ""):
            self.send_response(302)
            self.send_header("Set-Cookie", "chal=ok; Path=/")
            self.send_header("Location", self.path)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    print("PORT=%d" % srv.server_address[1], flush=True)
    srv.serve_forever()
