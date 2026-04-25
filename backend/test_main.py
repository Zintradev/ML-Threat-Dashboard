import pytest
from fastapi.testclient import TestClient
from main import app, rate_limiter, RealTimeMLModel

client = TestClient(app)

def test_read_root():
    """Prueba que el servidor arranca y responde en la raíz"""
    response = client.get("/")
    assert response.status_code == 200
    assert "Real Traffic ML Detection" in response.json()["message"]

def test_system_status():
    """Prueba el endpoint de estado del sistema"""
    response = client.get("/system/status")
    assert response.status_code == 200
    data = response.json()
    assert data["system"]["status"] == "operational"

def test_rule_based_sql_injection():
    """Prueba que el sistema de reglas detecta SQL Injection"""
    model = RealTimeMLModel()
    # Forzamos que no use ML para probar las reglas
    model.model = None 
    
    malicious_request = {
        "method": "GET",
        "url": "http://localhost",
        "path": "/login?user=' OR 1=1--",
        "query_params": {}
    }
    
    result = model.analyze_request(malicious_request)
    assert result["prediction"] == 1
    assert result["attack_type"] == "SQL Injection"

def test_rule_based_xss():
    """Prueba que el sistema de reglas detecta XSS"""
    model = RealTimeMLModel()
    model.model = None 
    
    malicious_request = {
        "method": "POST",
        "url": "http://localhost",
        "path": "/comment",
        "query_params": {"text": "<script>alert(1)</script>"}
    }
    
    result = model.analyze_request(malicious_request)
    assert result["prediction"] == 2
    assert result["attack_type"] == "XSS"

def test_rate_limiter():
    """Prueba que el límite de peticiones funciona"""
    from main import RateLimiter
    import time
    
    limiter = RateLimiter(max_requests=2, time_window=10)
    ip = "192.168.1.50"
    
    assert limiter.is_allowed(ip) == True  # Petición 1
    assert limiter.is_allowed(ip) == True  # Petición 2
    assert limiter.is_allowed(ip) == False # Petición 3 (Bloqueada)
