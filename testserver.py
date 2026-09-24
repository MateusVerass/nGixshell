#!/usr/bin/env python3
"""Test fixture server: echoes headers, simulates vhosts and a WAF."""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body=b"", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _route(self):
        LOG.append({"path": self.path, "host": self.headers.get("Host", ""),
                    "headers": dict(self.headers)})
        if "OR%201%3D1" in self.path or "%3Cscript%3E" in self.path.lower() or "../" in self.path:
            return self._send(403, b"Request blocked by ModSecurity\n")
        if self.path.startswith("/echo"):
            body = json.dumps(dict(self.headers)).encode()
            return self._send(200, body)
        if self.headers.get("Host", "").startswith("internal"):
            return self._send(200, b"INTERNAL ADMIN PORTAL " + b"X" * 600)
        if self.path.startswith("/nginx_status"):
            return self._send(200, b"Active connections: 3 \n"
                                   b"server accepts handled requests\n"
                                   b" 10 10 42 \n"
                                   b"Reading: 0 Writing: 1 Waiting: 2 \n")
        if self.path.startswith("/.env"):
            return self._send(200, b"DB_PASS=secret\n")
        if self.headers.get("Range"):
            # Simulates the CVE-2017-7529 signature (overflowed Content-Range)
            return self._send(416, b"", {"Content-Range":
                                         "bytes */18446744073709551615"})
        if self.path == "/":
            return self._send(200, b"ok\n",
                              {"ETag": '"6537cac7-267"', "Set-Cookie": "__cf_bm=1"})
        return self._send(404, b"not found\n")

    do_GET = _route
    do_HEAD = _route
    do_POST = _route

    def log_message(self, *a):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18081
    if len(sys.argv) > 2:
        Handler.server_version = sys.argv[2]
        Handler.sys_version = ""
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"fixture on {port} server={Handler.server_version}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
