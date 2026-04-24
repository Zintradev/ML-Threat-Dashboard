import requests
import asyncio
import aiohttp

async def check_all_connections():
    base_url = "http://localhost:8000"
    
    endpoints = [
        "/health",
        "/zap-status",
        "/diagnostics"
    ]
    
    async with aiohttp.ClientSession() as session:
        for endpoint in endpoints:
            try:
                async with session.get(f"{base_url}{endpoint}") as response:
                    if response.status == 200:
                        data = await response.json()
                        print(f"✅ {endpoint}: {data}")
                    else:
                        print(f"❌ {endpoint}: HTTP {response.status}")
            except Exception as e:
                print(f"❌ {endpoint}: {e}")

if __name__ == "__main__":
    asyncio.run(check_all_connections())