@echo off
echo [+] Starting ML Threat Dashboard...

docker compose up --build -d
if errorlevel 1 (
    echo docker compose failed or not found, falling back to docker-compose...
    docker-compose up --build -d
)

echo [+] Waiting 5 seconds for services to initialize...
timeout /t 5 /nobreak > NUL

echo [+] Opening browser...
start http://localhost:3000

echo [+] Attaching to logs (Press Ctrl+C to stop viewing logs)...
docker compose logs -f
if errorlevel 1 (
    docker-compose logs -f
)
