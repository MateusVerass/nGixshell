#!/usr/bin/env python3
"""Tiny HTTP backend used by the RCE lab.

Sleeps for `X-Delay` seconds (default 60) before replying, which keeps nginx's
request-body buffers alive while the exploit sprays fake ngx_pool_cleanup_s
records through POST bodies.
"""
import http.server
import socketserver
import time


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        try:
            delay = float(self.headers.get("X-Delay", "5"))
        except ValueError:
            delay = 5.0
        time.sleep(delay)
        body = b"backend ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _handle

    def log_message(self, *args):
        pass


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 19323), Handler) as srv:
    print("backend on 127.0.0.1:19323", flush=True)
    srv.serve_forever()
