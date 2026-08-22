# ML Threat Dashboard

A real-time cybersecurity dashboard that captures web traffic via proxy and analyzes it using Machine Learning to detect threats like SQL Injection, XSS, and DoS.

![Status](https://img.shields.io/badge/Status-Work_in_Progress-yellow)

## Architecture

- **Backend:** FastAPI, Mitmproxy (Traffic Capture), Scikit-learn (ML Model).
- **Frontend:** React, TypeScript, TailwindCSS.
- **Infrastructure:** Docker & Docker Compose.

## Quick Start (Docker)

The fastest way to launch the ML Threat Dashboard is using the provided startup scripts.

**On Windows:**
Double-click `start.bat` or run it from your terminal:
```cmd
start.bat
```

**On Linux/macOS:**
Make the script executable and run it:
```bash
chmod +x start.sh
./start.sh
```

Alternatively, you can manually build and start the containers:
1. `docker compose up --build -d`
2. Open the dashboard: http://localhost:3000
3. Backend API: http://localhost:8000

## Local Development Setup

### Backend (Python)

cd backend
python -m venv venv
source venv/bin/activate # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload

### Frontend (React)

cd frontend/ml-threat-dashboard
npm install
npm start

## How to Capture Traffic

1. Click "Start MITMProxy & Scan" on the Dashboard.
2. Configure your browser proxy to 127.0.0.1:8080.
3. Browse websites; the dashboard will analyze traffic in real-time.
