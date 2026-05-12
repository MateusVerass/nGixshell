#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "Building Docker image (compiles nginx from source)..."
docker compose build

echo ""
echo "Done. To run:"
echo ""
echo "  # Terminal 1 (server) — nginx runs with ASLR disabled (setarch -R):"
echo "  docker compose up"
echo ""
echo "  # Terminal 2 (attacker):"
echo "  python3 poc.py --cmd 'touch /tmp/pwned'"
echo ""
echo "  # Verify RCE:"
echo "  docker compose exec nginx ls -la /tmp/pwned"
echo "  docker compose exec nginx cat /tmp/pwned"
