# Nginx Rift Exploit

**CVE:** CVE-2026-42945  
**Tested on:** Ubuntu 24.04.3 LTS

## Usage

1. Run `./setup.sh` to create the container.
2. Run `docker compose -f env/docker-compose.yml up` to start the vulnerable nginx server.
3. Run `python3 poc.py --shell` to achieve RCE (Remote Code Execution).