# ML Threat Dashboard

A real-time cybersecurity dashboard that captures web traffic via proxy and analyzes it using Machine Learning to detect threats like SQL Injection, XSS, and DoS.

## Architecture
- **Backend:** FastAPI, Mitmproxy (Traffic Capture), Scikit-learn (ML Model).
- **Frontend:** React, TypeScript, TailwindCSS.
- **Infrastructure:** Docker & Docker Compose.

## Quick Start (Docker)
The easiest way to run the project is using Docker.

1. Build and start the containers:
   ```bash
   docker-compose up --build
