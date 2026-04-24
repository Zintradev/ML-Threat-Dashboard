import requests
import threading
import time
import random

# CONFIGURACIÓN CORRECTA - Usar MITMProxy
PROXY = {
    "http": "http://127.0.0.1:8080", 
    "https": "http://127.0.0.1:8080"
}
BASE_URL = "http://testphp.vulnweb.com"

def sql_injection_attack():
    """Generar ataques SQL Injection"""
    print("[SQL] Iniciando ataques SQL Injection...")
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
            response = requests.get(url, proxies=PROXY, timeout=5)
            print(f"[SQL] Ataque #{i+1}: {payload[:30]}... -> Status: {response.status_code}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[ERROR SQL]: {e}")

def xss_attack():
    """Generar ataques XSS"""
    print("[XSS] Iniciando ataques XSS...")
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
            response = requests.get(url, proxies=PROXY, timeout=5)
            print(f"[XSS] Ataque #{i+1}: {payload[:20]}... -> Status: {response.status_code}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[ERROR XSS]: {e}")

def dos_attack():
    """Simular ataque DoS"""
    print("[DOS] Iniciando ataque DoS (30 requests rápidas)...")
    time.sleep(2)
    
    for i in range(30):
        try:
            response = requests.get(BASE_URL, proxies=PROXY, timeout=3)
            if (i + 1) % 10 == 0:
                print(f"[DOS] Request #{(i + 1)}/30 -> Status: {response.status_code}")
            time.sleep(0.1)
        except Exception as e:
            print(f"[ERROR DOS #{i+1}]: {e}")

def directory_traversal():
    """Ataques Directory Traversal"""
    print("[DIR] Iniciando Directory Traversal...")
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
            response = requests.get(url, proxies=PROXY, timeout=5)
            print(f"[DIR] Ataque #{i+1}: {path} -> Status: {response.status_code}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[ERROR DIR]: {e}")

def normal_traffic():
    """Generar tráfico normal para comparar"""
    print("[NORMAL] Generando tráfico normal...")
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
            response = requests.get(url, proxies=PROXY, timeout=5)
            print(f"[NORMAL] Traffic #{i+1}: {path} -> Status: {response.status_code}")
            time.sleep(1)
        except Exception as e:
            print(f"[ERROR NORMAL]: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("GENERANDO ATAQUES AUTOMATICOS CON MITMPROXY")
    print("Asegurate de que MITMProxy este ejecutandose en puerto 8080")
    print("=" * 60)
    
    # Ejecutar en secuencia para mejor visualización
    sql_injection_attack()
    xss_attack() 
    dos_attack()
    directory_traversal()
    normal_traffic()
    
    print("=" * 60)
    print("TODOS LOS ATAQUES COMPLETADOS!")
    print("Revisa el dashboard en http://localhost:3000")
    print("Deberias ver amenazas detectadas en ROJO")
    print("=" * 60)