#task_nmap.py
import re
import socket
from urllib.parse import urlparse
from ai_core import AICore
from config import NMAP_BIN
def execute_nmap_scan(target_url, simulator_mode=False):
    print(f"--- Starting NMAP Task for URL: {target_url} ---")
    parsed_url = urlparse(target_url)
    target_host = parsed_url.hostname or target_url.replace('http://', '').replace('https://', '').split('/')[0]
    if ':' in target_host:
        target_host = target_host.split(':')[0]
    print(f"[NMAP] Target host: {target_host}")
    if simulator_mode:
        print("[NMAP] Running in simulator mode")
        return {
            "open_ports": ["22/tcp", "80/tcp", "443/tcp", "8000/tcp"],
            "services": ["ssh", "http", "https", "http-alt"],
        }
    nmap_command = [
        NMAP_BIN, '-sT', '-sV', '--open', '--host-timeout', '30s', '--max-retries', '2',
        '-p', '22,80,135,443,3000,3306,3389,5000,5432,8000,8080,8443,8888,9000',
        '--version-intensity', '5', target_host
    ]
    print(f"[NMAP] Executing: {' '.join(nmap_command)}")
    nmap_output = AICore.run_command(nmap_command)
    if nmap_output:
        open_ports = re.findall(r'(\d+/tcp\s+open\s+\S+)', nmap_output)
        print(f"[NMAP] Found {len(open_ports)} open ports: {open_ports}")
        return {"open_ports": open_ports}
    else:
        print("[NMAP] Nmap scan failed or produced no output.")
        return {"open_ports": []}