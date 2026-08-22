import requests
import threading
import time
import random

PROXY = {
    "http": "http://127.0.0.1:8080", 
    "https": "http://127.0.0.1:8080"
}
BASE_URL = "http://testphp.vulnweb.com"

def sql_injection_attack():
    """Generate SQL Injection attacks"""
    print("[SQL] Starting SQL Injection attacks...")
    payloads = [
        "' OR '1'='1",
        "admin'--",
        "' UNION SELECT 1,2,3--", 
        "' AND 1=1--",
        "'; DROP TABLE users--",
        "' OR 'a'='a"
    ]
    
    for i, payload in enumerate(payloads):
        try:
            url = f"{BASE_URL}/search.php?q={payload}"
            response = requests.get(url, proxies=PROXY, timeout=0.1)
            print(f"[SQL] Attack #{i+1}: {payload[:30]}... -> Status: {response.status_code}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[ERROR SQL]: {e}")

def xss_attack():
    """Generate XSS attacks"""
    print("[XSS] Starting XSS attacks...")
    time.sleep(1)
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<body onload=alert('XSS')>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ]
    
    for i, payload in enumerate(payloads):
        try:
            url = f"{BASE_URL}/search.php?q={payload}"
            response = requests.get(url, proxies=PROXY, timeout=0.1)
            print(f"[XSS] Attack #{i+1}: {payload[:20]}... -> Status: {response.status_code}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[ERROR XSS]: {e}")

def dos_attack():
    """Simulate DoS attack (Rate Limit Trigger)"""
    print("[DOS] Starting DoS attack (50 rapid requests)...")
    time.sleep(2)
    
    # Send requests very fast to trigger rate limiter (15 req / 10 sec)
    for i in range(50):
        try:
            # Use small timeout to not hang when the server rate limits/drops connection
            response = requests.get(BASE_URL, proxies=PROXY, timeout=0.1)
            if (i + 1) % 10 == 0:
                print(f"[DOS] Request #{(i + 1)}/50 -> Status: {response.status_code}")
        except requests.exceptions.Timeout:
            # Expected during DoS as connection is dropped or throttled
            if (i + 1) % 10 == 0:
                print(f"[DOS] Request #{(i + 1)}/50 -> Timeout (Expected)")
        except requests.exceptions.ConnectionError:
            if (i + 1) % 10 == 0:
                print(f"[DOS] Request #{(i + 1)}/50 -> ConnectionError (Expected)")
        except Exception as e:
            print(f"[ERROR DOS #{i+1}]: {e}")
        
        # Extremely small delay to fire rapidly
        time.sleep(0.01)

def directory_traversal():
    """Directory Traversal attacks"""
    print("[DIR] Starting Directory Traversal...")
    time.sleep(3)
    
    paths = [
        "../../../etc/passwd",
        "../../windows/win.ini", 
        "../config.php",
        "....//....//....//etc/passwd"
    ]
    
    for i, path in enumerate(paths):
        try:
            url = f"{BASE_URL}/{path}"
            response = requests.get(url, proxies=PROXY, timeout=0.1)
            print(f"[DIR] Attack #{i+1}: {path} -> Status: {response.status_code}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[ERROR DIR]: {e}")

def normal_traffic():
    """Generate normal traffic for comparison"""
    print("[NORMAL] Generating normal traffic...")
    time.sleep(4)
    
    normal_paths = [
        "/",
        "/index.php", 
        "/products.php",
        "/categories.php",
        "/about.php"
    ]
    
    for i, path in enumerate(normal_paths):
        try:
            url = BASE_URL + path
            response = requests.get(url, proxies=PROXY, timeout=0.1)
            print(f"[NORMAL] Traffic #{i+1}: {path} -> Status: {response.status_code}")
            # Sleep enough to NOT trigger rate limit
            time.sleep(1.0)
        except Exception as e:
            print(f"[ERROR NORMAL]: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("GENERATING AUTOMATED ATTACKS WITH MITMPROXY")
    print("Ensure MITMProxy is running on port 8080")
    print("=" * 60)
    
    # Execute in sequence for better visualization
    sql_injection_attack()
    xss_attack() 
    directory_traversal()
    normal_traffic()
    dos_attack()
    
    print("=" * 60)
    print("ALL ATTACKS COMPLETED!")
    print("Check the dashboard at http://localhost:3000")
    print("You should see threats detected in RED with MITRE IDs")
    print("=" * 60)
