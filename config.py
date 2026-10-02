#config.py
import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Wordlist configuration (defaults to wordlist.txt in project root)
DEFAULT_WORDLIST = os.path.join(BASE_DIR, "wordlist.txt")
GOBUSTER_WORDLIST = DEFAULT_WORDLIST

def get_gobuster_path():
    """Find the gobuster executable."""
    # 1. Project root
    local_path = os.path.join(BASE_DIR, "gobuster.exe")
    if os.path.exists(local_path):
        return local_path
    # 2. System PATH
    which_path = shutil.which("gobuster")
    if which_path:
        return which_path
    # 3. Downloads extraction folder fallback
    downloads_path = r"C:\Users\Pravin.Tambe\Downloads\gobuster_Windows_x86_64\gobuster.exe"
    if os.path.exists(downloads_path):
        return downloads_path
    return "gobuster"

def get_nmap_path():
    """Find the nmap executable."""
    # 1. System PATH
    which_path = shutil.which("nmap")
    if which_path:
        return which_path
    # 2. Standard Windows installation locations
    std_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe"
    ]
    for p in std_paths:
        if os.path.exists(p):
            return p
    return "nmap"

GOBUSTER_BIN = get_gobuster_path()
NMAP_BIN = get_nmap_path()

