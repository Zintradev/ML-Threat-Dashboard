import pytest
from fastapi.testclient import TestClient
from main import app, MLModel, RateLimiter

client = TestClient(app)

def test_system_status():
    """Prueba el endpoint de estado del sistema"""
    response = client.get("/system/status")
    assert response.status_code == 200
    data = response.json()
    assert data["system"]["status"] == "operational"

def test_rule_based_sql_injection():
    """Prueba que el sistema de reglas detecta SQL Injection"""
    model = MLModel()
    # Forzamos que no use ML para probar las reglas
    model.model = None 
    
    malicious_request = {
        "method": "GET",
        "url": "http://localhost",
        "path": "/login?user=' OR 1=1--",
    }
    
    result = model.analyze(malicious_request)
    assert result["prediction"] == 1
    assert result["attack_type"] == "SQL Injection"

def test_rule_based_xss():
    """Prueba que el sistema de reglas detecta XSS"""
    model = MLModel()
    model.model = None 
    
    malicious_request = {
        "method": "POST",
        "url": "http://localhost",
        "path": "/comment?text=<script>alert(1)</script>",
    }
    
    result = model.analyze(malicious_request)
    assert result["prediction"] == 2
    assert result["attack_type"] == "XSS"

def test_rate_limiter():
    """Prueba que el límite de peticiones funciona"""
    limiter = RateLimiter()
    ip = "192.168.1.50"
    
    # Hacemos 50 peticiones permitidas (límite actual en main.py)
    for _ in range(50):
        assert limiter.is_allowed(ip) == True
        
    # La petición 51 debe ser bloqueada
    assert limiter.is_allowed(ip) == False
