import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.services.ml_service import MLService
from app.services.rate_limiter import RateLimiter

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.mark.anyio
async def test_system_status():
    """Test the system status endpoint asynchronously"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/system/status")
        assert response.status_code == 200
        data = response.json()
        assert data["system"]["status"] == "operational"

def test_ml_service_reconstruct_request():
    """Test the string reconstruction logic for NLP input"""
    service = MLService()
    # Mocking pipeline to avoid failure during instantiation if pkl is missing
    service.pipeline = None 
    
    req = {
        "method": "POST",
        "path": "/login",
        "query_params": {"user": "admin'--"}
    }
    
    reconstructed = service.reconstruct_request(req)
    assert reconstructed == "POST /login?user=admin'-- HTTP/1.1"
    
    # Test without query params
    req_no_params = {
        "method": "GET",
        "path": "/about.html"
    }
    assert service.reconstruct_request(req_no_params) == "GET /about.html HTTP/1.1"

def test_rate_limiter():
    """Test the DoS rate limiter (threshold is 15 req / 10 sec)"""
    limiter = RateLimiter(max_requests=15, time_window=10)
    ip = "192.168.1.50"
    
    # First 14 requests should be allowed
    for _ in range(14):
        assert limiter.is_allowed(ip) is True
        
    # The 15th request should still be allowed, but 16th will fail
    assert limiter.is_allowed(ip) is True
    assert limiter.is_allowed(ip) is False