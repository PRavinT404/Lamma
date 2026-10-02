#task_gobuster.py
import re
import os
from urllib.parse import urlparse
from ai_core import AICore
from config import GOBUSTER_WORDLIST, GOBUSTER_BIN
def execute_gobuster_scan(target_url, simulator_mode=False):
    print(f"[GOBUSTER] Starting directory scan for: {target_url}")
    if simulator_mode:
        print("[GOBUSTER] Running in simulator mode")
        return {"found_directories": ["/admin", "/api", "/dashboard"]}
    wordlist = GOBUSTER_WORDLIST
    if not os.path.exists(wordlist):
        print(f"[GOBUSTER] ERROR: Wordlist not found at the path specified in config.py: {wordlist}")
        print("[GOBUSTER] Please check the path in config.py.")
        return {"found_directories": []}
    gobuster_command = [
        GOBUSTER_BIN, 'dir', '-u', target_url, '-w',
        wordlist,
        '-t', '50', '--no-error'
    ]
    print(f"[GOBUSTER] Executing: {' '.join(gobuster_command)}")
    gobuster_output = AICore.run_command(gobuster_command)
    if gobuster_output:
        raw_matches = re.findall(r'(\S+)\s+\(Status:', gobuster_output)
        found = [('/' + m.lstrip('/')) for m in raw_matches if not m.startswith('=')]
        print(f"[GOBUSTER] Found {len(found)} directories: {found}")
        return {"found_directories": found}
    else:
        print("[GOBUSTER] Scan failed or produced no output.")
        return {"found_directories": []}