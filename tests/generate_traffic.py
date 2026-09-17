"""
Traffic Generator & Security Simulation Testbed
------------------------------------------------
Sends realistic HTTP traffic to the target website (http://127.0.0.1:8001):
1. Normal user browsing scenarios (catalog, search, standard login).
2. SQL injection attack vectors.
3. Cross-Site Scripting (XSS) vectors.
4. Behavioral Brute-Force login attacks.
5. High-frequency rate limit spike test.
"""

import time
import requests
import urllib.parse

TARGET_URL = "http://127.0.0.1:8001"

def test_normal_browsing():
    print("\n[+] 1. Simulating Normal User Browsing...")
    endpoints = [
        "/",
        "/search?q=laptop",
        "/search?q=mechanical+keyboard",
        "/api/products",
        "/login"
    ]
    for ep in endpoints:
        url = f"{TARGET_URL}{ep}"
        try:
            r = requests.get(url, timeout=2)
            print(f"  [GET] {ep} -> Status: {r.status_code}")
            time.sleep(0.4)
        except Exception as e:
            print(f"  [-] Target unreachable: {e}")

def test_sqli_attack():
    print("\n[+] 2. Simulating SQL Injection Attacks (Safe Payloads)...")
    sqli_payloads = [
        "' OR '1'='1",
        "1' UNION SELECT username, password FROM users--",
        "1; DROP TABLE users--"
    ]
    for p in sqli_payloads:
        url = f"{TARGET_URL}/search?q={urllib.parse.quote(p)}"
        try:
            r = requests.get(url, timeout=2)
            print(f"  [SQLi Test] /search?q={p} -> Status: {r.status_code}")
            time.sleep(0.6)
        except Exception as e:
            print(f"  [-] Target unreachable: {e}")

def test_xss_attack():
    print("\n[+] 3. Simulating XSS Attack Vectors...")
    xss_payloads = [
        "<script>alert('XSS_DEMO')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(document.cookie)>"
    ]
    for p in xss_payloads:
        url = f"{TARGET_URL}/search?q={urllib.parse.quote(p)}"
        try:
            r = requests.get(url, timeout=2)
            print(f"  [XSS Test] /search?q={p} -> Status: {r.status_code}")
            time.sleep(0.6)
        except Exception as e:
            print(f"  [-] Target unreachable: {e}")

def test_brute_force():
    print("\n[+] 4. Simulating Behavioral Brute-Force Login Attack (6 Rapid Failed Attempts)...")
    login_url = f"{TARGET_URL}/login"
    for i in range(1, 7):
        data = {"username": "admin", "password": f"wrongPass_{i}"}
        try:
            r = requests.post(login_url, data=data, timeout=2)
            print(f"  [Attempt {i}/6] Failed Login -> Status: {r.status_code}")
            time.sleep(0.3)
        except Exception as e:
            print(f"  [-] Target unreachable: {e}")

def test_rate_spike():
    print("\n[+] 5. Simulating High-Frequency Request Burst (30 requests)...")
    for i in range(30):
        try:
            requests.get(f"{TARGET_URL}/api/products", timeout=1)
        except Exception:
            pass
    print("  [✓] Sent 30 burst requests.")

if __name__ == "__main__":
    print("==================================================")
    print("   AI Web Threat Defense - Traffic Simulation     ")
    print("==================================================")
    print("Select test scenario:")
    print("1. Run All Tests (Normal -> SQLi -> XSS -> BruteForce)")
    print("2. Normal Traffic Only")
    print("3. SQL Injection Test Only")
    print("4. XSS Attack Test Only")
    print("5. Behavioral Brute Force Attack Only")
    print("6. High Frequency Burst Test Only")

    import sys
    choice = sys.argv[1] if len(sys.argv) > 1 else "1"

    if choice == "1":
        test_normal_browsing()
        test_sqli_attack()
        test_xss_attack()
        test_brute_force()
    elif choice == "2":
        test_normal_browsing()
    elif choice == "3":
        test_sqli_attack()
    elif choice == "4":
        test_xss_attack()
    elif choice == "5":
        test_brute_force()
    elif choice == "6":
        test_rate_spike()
