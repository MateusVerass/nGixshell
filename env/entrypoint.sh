#!/bin/sh
# Launch nginx with ASLR disabled so heap addresses are deterministic — this is
# a hard requirement of the CVE-2026-42945 exploit (see README).
# If you only want to use the scanner, ASLR does not matter.
set -e

if command -v setarch >/dev/null 2>&1; then
    # The personality() syscall is blocked by the default seccomp profile;
    # docker-compose.yml sets seccomp=unconfined like the vendor lab does.
    if setarch "$(uname -m)" -R true 2>/dev/null; then
        exec setarch "$(uname -m)" -R /docker-entrypoint.sh nginx -g "daemon off;"
    fi
    echo "[entrypoint] WARNING: could not disable ASLR (setarch -R denied)." >&2
    echo "[entrypoint] The exploit will not work; the scanner still will." >&2
fi

exec /docker-entrypoint.sh nginx -g "daemon off;"
