# FILE: debug_nmap.py
# PURPOSE: Test what nmap actually returns for your target

from task_nmap import execute_nmap_scan

# Test what nmap actually returns for your target
target = "http://localhost/DVWA/"
print(f"Testing nmap scan for: {target}")
print("="*50)

result = execute_nmap_scan(target)
print(f"Nmap result: {result}")

if result and result.get("open_ports"):
    print("\nOpen ports found:")
    for port in result['open_ports']:
        print(f"  - Port {port['port']}: {port['service']} ({port.get('version', 'Unknown')})")
    
    # Check if HTTP ports are detected
    http_ports = [80, 443, 8080, 8443]
    found_http = any(p['port'] in http_ports for p in result['open_ports'])
    print(f"\nHTTP service detected: {found_http}")
else:
    print("\n❌ No open ports found or nmap failed!")
    print("This is why the agent can't proceed to web testing.")

def save_scan_results(results, filename):
    """Save scan results to a file."""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Scan results saved to {filename}")
    except Exception as e:
        print(f"Error saving scan results: {e}")

if __name__ == "__main__":
    target = "127.0.0.1"
    results = main(target)
    if results:
        save_scan_results(results, "nmap_scan.txt")
