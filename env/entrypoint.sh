#!/bin/sh
# Start the backend and nginx with ASLR disabled (setarch -R).
# ASLR off is a hard requirement of the CVE-2026-42945 exploit: heap addresses
# must be deterministic for the calibration profile to stay valid.
# seccomp=unconfined is required for the personality() syscall (see compose).
set -e
cd /app

python3 server.py &>/dev/null &

if command -v setarch >/dev/null 2>&1; then
    if setarch "$(uname -m)" -R true 2>/dev/null; then
        exec setarch "$(uname -m)" -R /nginx-src/build/nginx -p /app -c /app/nginx.conf
    fi
    echo "[entrypoint] WARNING: could not disable ASLR (setarch -R denied)." >&2
    echo "[entrypoint] The exploit will not work; the scanner still will." >&2
fi

exec /nginx-src/build/nginx -p /app -c /app/nginx.conf
