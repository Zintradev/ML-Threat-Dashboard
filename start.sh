#!/usr/bin/env bash

echo "[+] Starting ML Threat Dashboard..."

if docker compose version &> /dev/null; then
    DOCKER_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    DOCKER_CMD="docker-compose"
else
    echo "[-] Error: Docker Compose is not installed or not in PATH."
    exit 1
fi

$DOCKER_CMD up --build -d

echo "[+] Waiting 5 seconds for services to initialize..."
sleep 5

echo "[+] Opening browser..."
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:3000
elif command -v open &> /dev/null; then
    open http://localhost:3000
else
    echo "[-] Could not detect web browser launcher. Please open http://localhost:3000 manually."
fi

echo "[+] Attaching to logs (Press Ctrl+C to stop viewing logs)..."
$DOCKER_CMD logs -f
