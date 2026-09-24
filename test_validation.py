#!/usr/bin/env python3
"""Validation battery for nGixShell.

Usage: python3 test_validation.py [path/to/nGixshell]
Runs unit tests against the imported module and integration tests via CLI,
using local HTTP/TLS fixtures and HTTP CONNECT / SOCKS5 proxy servers.
"""
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                       else os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import ngixshell as n  # noqa: E402

PY = sys.executable
RESULTS = []


def check(name, cond, detail="", warn=False):
    status = "PASS" if cond else ("WARN" if warn else "FAIL")
    RESULTS.append((status, name, detail))
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""), flush=True)
    return cond


def run_cli(args, timeout=180):
    p = subprocess.run([PY, os.path.join(REPO, "ngixshell.py")] + args,
                       capture_output=True, text=True, timeout=timeout,
                       cwd=tempfile.gettempdir())
    return p.returncode, p.stdout + p.stderr


# ─────────────────────────── fixtures ────────────────────────────────────────

def start_fixture(port, server="nginx/1.17.6"):
    p = subprocess.Popen([PY, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "testserver.py"), str(port), server],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"fixture {port} did not start")


class ConnectProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=5)
        except OSError:
            self.send_error(502)
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._pipe_both(self.connection, upstream)

    @staticmethod
    def _pipe_both(a, b):
        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
        t1 = threading.Thread(target=pipe, args=(a, b), daemon=True)
        t2 = threading.Thread(target=pipe, args=(b, a), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()

    def log_message(self, *a):
        pass


def start_connect_proxy(port=18090):
    srv = ThreadingHTTPServer(("127.0.0.1", port), ConnectProxyHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def start_socks5(port=18091):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    def handle(c):
        try:
            ver, nm = c.recv(2)
            c.recv(nm)
            c.sendall(b"\x05\x00")
            hdr = c.recv(4)
            atyp = hdr[3]
            if atyp == 1:
                addr = socket.inet_ntoa(c.recv(4))
            elif atyp == 3:
                ln = c.recv(1)[0]
                addr = c.recv(ln).decode()
            else:
                addr = socket.inet_ntop(socket.AF_INET6, c.recv(16))
            port_ = struct.unpack(">H", c.recv(2))[0]
            up = socket.create_connection((addr, port_), timeout=5)
            c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") +
                      struct.pack(">H", 0))
            ConnectProxyHandler._pipe_both(c, up)
        except Exception:
            pass

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


def make_tls_server(port=18092, days=2):
    d = tempfile.mkdtemp(prefix="ngix_tls_")
    key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout",
                    key, "-out", crt, "-days", str(days), "-nodes",
                    "-subj", "/CN=tlstest.local",
                    "-addext", "subjectAltName=DNS:tlstest.local"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # no TLS 1.3

    def serve(s):
        try:
            s.recv(4096)
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"
                      b"Connection: close\r\n\r\nok\n")
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    raw = socket.socket()
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("127.0.0.1", port))
    raw.listen(8)

    def loop():
        while True:
            try:
                c, _ = raw.accept()
            except OSError:
                return
            try:
                s = ctx.wrap_socket(c, server_side=True)
            except Exception:
                try:
                    c.close()
                except Exception:
                    pass
                continue  # failed handshake must not kill the listener
            threading.Thread(target=serve, args=(s,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return crt, d


# ─────────────────────────── tests ───────────────────────────────────────────

def main():
    fixture = start_fixture(18081, "nginx/1.17.6")
    fixture_v = start_fixture(18082, "nginx/1.13.2")
    start_connect_proxy(18090)
    start_socks5(18091)
    make_tls_server(18092)

    # 1-5 CLI basics ------------------------------------------------------
    rc, out = run_cli(["--help"])
    check("cli: --help", rc == 0 and "--build-file" in out and "--verify-url" in out)

    rc, out = run_cli(["--list-cves"])
    check("cli: --list-cves", rc == 0 and "CVE-2026-42945" in out and "8.1" in out
          and "SAME-ADVISORY" not in out)

    rc, out = run_cli(["--list-candidates"])
    check("cli: --list-candidates", rc == 0 and "SAFE" in out)

    rc, out = run_cli(["127.0.0.1:18082", "--cve", "CVE-2017-7529"])
    check("cli: probe CVE-2017-7529 positive (1.13.2 + overflowed Content-Range)",
          "VULNERABLE" in out, out.splitlines()[-6] if out else "")

    rc, out = run_cli(["127.0.0.1:18081", "--cve", "CVE-2017-7529"])
    check("cli: probe CVE-2017-7529 negative (1.17.6 patched)",
          "PATCHED" in out)

    # 6 scan + audit ------------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        h = os.path.join(td, "s.html")
        rc, out = run_cli(["127.0.0.1:18081", "--json", "--html-report", h,
                           "--skip-vhosts"])
        data = None
        try:
            data = json.loads(out[out.index("{"):out.rindex("}") + 1])
        except Exception:
            pass
        check("scan: --json parses", data is not None)
        check("scan: fingerprint nginx + version",
              data and data["fingerprint"]["version"] == "1.17.6")
        check("scan: header audit issues reported",
              data and len(data["web_audit"]["header_issues"]) >= 5)
        check("scan: server version leak flagged",
              data and any(i["header"] == "server" for i in data["web_audit"]["header_issues"]))
        check("scan: path discovery found /.env and /nginx_status",
              data and {p["path"] for p in data["web_audit"]["paths_found"]} >=
              {"/.env", "/nginx_status"})
        check("scan: stub_status parsed",
              data and data["web_audit"]["stub_status"].get("active_connections") == 3)
        check("scan: nginx-style ETag detected as nginx",
              data and data["fingerprint"]["is_nginx"] is True)
        check("scan: html report written", os.path.exists(h))
        html_txt = open(h, encoding="utf-8").read()
        check("scan: html contains CVE table", "CVE-2026-42945" in html_txt)

    # 7 vhost -------------------------------------------------------------
    rc, out = run_cli(["127.0.0.1:18081", "--skip-paths", "--skip-headers",
                       "--skip-tls", "--json"])
    try:
        data = json.loads(out[out.index("{"):out.rindex("}") + 1])
        vhosts = [v["vhost"] for v in data["web_audit"]["vhosts_found"]]
    except Exception:
        vhosts = []
    check("scan: vhost enumeration finds 'internal'", "internal" in vhosts, str(vhosts))

    # 8 WAF detect --------------------------------------------------------
    rc, out = run_cli(["127.0.0.1:18081", "--waf-detect", "--skip-paths",
                       "--skip-vhosts", "--skip-tls", "--skip-headers"])
    check("scan: WAF detection (ModSecurity behaviour)", "WAF DETECTED" in out
          and "ModSecurity" in out)

    # 9 multi-target ------------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        tf = os.path.join(td, "hosts.txt")
        h = os.path.join(td, "multi.html")
        open(tf, "w").write("127.0.0.1:18081\n127.0.0.1:18082\n")
        rc, out = run_cli(["--target-file", tf, "--json", "--html-report", h,
                           "--skip-paths", "--skip-vhosts", "--skip-tls",
                           "--skip-headers"])
        try:
            data = json.loads(out[out.index("{"):out.rindex("}") + 1])
        except Exception:
            data = {}
        check("multi: JSON has 2 targets",
              isinstance(data.get("targets"), list) and len(data["targets"]) == 2)
        htmls = [f for f in os.listdir(td) if f.endswith(".html")]
        check("multi: one HTML report per target", len(htmls) == 2, str(htmls))

    # 10 error handling ---------------------------------------------------
    rc, out = run_cli(["127.0.0.1:18081", "--cmd", "id", "--build-file",
                       "/nonexistent/profile.json"])
    check("exploit: missing --build-file handled",
          rc == 1 and "Cannot load calibration" in out and "Traceback" not in out)

    rc, out = run_cli(["127.0.0.1:18081", "--cmd", "id", "--offsets", "zzz,0x10",
                       "--tries", "1", "--spray", "1"])
    check("exploit: invalid offset warns, valid one accepted",
          "Ignoring invalid offset 'zzz'" in out)

    rc, out = run_cli(["127.0.0.1:18081", "--cmd", "id", "--tries", "1", "--spray", "1"])
    check("exploit: no crash on fixture → NO CRASH verdict",
          "NO CRASH" in out and rc == 1)

    # 11 subdomain scan (localtest.me → 127.0.0.1) ------------------------
    with tempfile.TemporaryDirectory() as td:
        wl = os.path.join(td, "wl.txt")
        open(wl, "w").write("www\napi\n")
        rc, out = run_cli(["--subdomain-scan", "localtest.me", "--wordlist", wl,
                           "--scan-port", "18081", "--scan-timeout", "2"])
        check("subdomain: www.localtest.me probed and reported",
              "www.localtest.me" in out, out.strip().splitlines()[-1] if out else "")

    # 12 unit: waf bypass headers / path obfuscation ----------------------
    n._waf_bypass = True
    n._waf_spoof_ip = "10.9.9.9"
    h = n._build_headers("t.local", {"Range": "bytes=1-"})
    ok = all(k in h for k in ("X-Forwarded-For", "X-Real-IP", "True-Client-IP",
                              "X-Originating-IP", "X-Remote-IP", "X-Client-IP"))
    check("unit: WAF spoof headers present", ok)
    wire = n._headers_to_wire(h)
    check("unit: spoof header reaches the wire (case-insensitive)",
          b"x-forwarded-for" in wire.lower() and b"10.9.9.9" in wire)
    variants = {n._waf_obfuscate_path("/admin") for _ in range(40)}
    check("unit: path obfuscation produces multiple variants", len(variants) >= 3,
          f"{len(variants)} variants")
    n._waf_bypass = False

    # 13 unit: rate limiter -------------------------------------------------
    rl = n.RateLimiter(5)
    t0 = time.monotonic()
    for _ in range(3):
        rl.acquire()
    dt = time.monotonic() - t0
    check("unit: RateLimiter(5rps) throttles 3 requests ≥0.4s", dt >= 0.4, f"{dt:.2f}s")

    # 14 unit: parse_offsets / load_calibration -----------------------------
    offs = n.parse_offsets("0x10, 0x20, 32")
    check("unit: parse_offsets hex list", offs == [16, 32, 0x32], str(offs))
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"heap_base": "0x555555659000", "libc_base": 0x7ffff77ba000,
                   "sys_offset": 0x50d70, "offsets": ["0x100", 0x200]}, f)
        cal_path = f.name
    cal = n.load_calibration(cal_path)
    check("unit: load_calibration computes system_addr",
          cal["system_addr"] == 0x7ffff77ba000 + 0x50d70 and cal["offsets"] == [0x100, 0x200])
    os.unlink(cal_path)

    # 15 unit: html escaping -------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        evil_fp = {"server_header": "<script>alert(1)</script>", "is_nginx": True}
        h = os.path.join(td, "evil.html")
        n.generate_html_report("evil<host>", 80, [], evil_fp, None, 0.0, h)
        txt = open(h, encoding="utf-8").read()
        check("unit: HTML report escapes target-controlled data",
              "<script>alert(1)</script>" not in txt and "&lt;script&gt;" in txt)

    # 16 unit: custom headers / auth / cookie reach the server ---------------
    n._extra_headers.clear()
    n._extra_headers["X-Test"] = "abc"
    n._extra_headers["Authorization"] = "Basic dGVzdDp0ZXN0"
    n._extra_headers["Cookie"] = "sid=42"
    status, hdrs, body = n._http_get("127.0.0.1", 18081, "/echo")
    echoed = json.loads(body)
    check("unit: --header/--auth/--cookie are sent",
          echoed.get("X-Test") == "abc" and "Basic" in echoed.get("Authorization", "")
          and echoed.get("Cookie") == "sid=42")
    n._extra_headers.clear()

    # 17 proxies -------------------------------------------------------------
    status, _, _ = n._http_get("127.0.0.1", 18081, "/", proxy="http://127.0.0.1:18090")
    check("proxy: HTTP CONNECT works", status == 200)
    status, _, _ = n._http_get("127.0.0.1", 18081, "/", proxy="socks5://127.0.0.1:18091")
    check("proxy: SOCKS5 works", status == 200)

    # 18 TLS ------------------------------------------------------------------
    res = n.tls_audit("127.0.0.1", 18092)
    issues = [i["issue"] for i in res.get("issues", [])]
    check("tls: self-signed cert flagged", any("Self-signed" in i for i in issues))
    check("tls: expiring cert flagged", any("expires in" in i for i in issues), str(issues))
    check("tls: TLS 1.3 not supported reported",
          res["protocols"].get("TLSv1_3") is False)
    fp = n.fingerprint_target("127.0.0.1", 18092, tls=True)
    check("tls: fingerprint captures cert CN", fp.get("tls_cn") == "tlstest.local",
          str(fp.get("tls_cn")))

    # 19 verify-url ------------------------------------------------------------
    check("unit: _verify_effect 200", n._verify_effect("http://127.0.0.1:18081/", False, None))
    check("unit: _verify_effect 404", not n._verify_effect("http://127.0.0.1:18081/nope", False, None))

    fixture.terminate(); fixture_v.terminate()

    fails = [r for r in RESULTS if r[0] == "FAIL"]
    warns = [r for r in RESULTS if r[0] == "WARN"]
    print(f"\n==== {len(RESULTS)} tests: "
          f"{len(RESULTS) - len(fails) - len(warns)} pass, {len(warns)} warn, "
          f"{len(fails)} fail ====")
    for _, name, detail in fails:
        print(f"  FAIL: {name} {detail}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
