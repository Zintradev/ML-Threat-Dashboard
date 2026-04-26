import pytest
from httpx import ASGITransport, AsyncClient
from main import app, MLModel, RateLimiter

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.mark.anyio
async def test_system_status():
    """Prueba el endpoint de estado del sistema de forma asíncrona"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/system/status")
        assert response.status_code == 200
        data = response.json()
        assert data["system"]["status"] == "operational"

def test_rule_based_sql_injection():
    model = MLModel()
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
    limiter = RateLimiter()
    ip = "192.168.1.50"
    for _ in range(50):
        assert limiter.is_allowed(ip) == True
    assert limiter.is_allowed(ip) == False