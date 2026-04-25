# Setup Guide: Virtual Environment and Docker

## 🐳 Dockerizing the Project (Recommended)

This is the easiest way to run the project on any device.

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed

### Installation and Execution

1.  **Clone the repository** (if you are on another device):
    ```bash
    git clone https://github.com/Zintradev/ML-Threat-Dashboard.git
    cd ML-Threat-Dashboard
    ```

2.  **Run with Docker Compose**:
    ```powershell
    docker-compose up --build
    ```
    *The `--build` flag ensures images are built with the latest changes.*

3.  **Access the application**:
    - **Frontend (Dashboard)**: [http://localhost:3000](http://localhost:3000)
    - **Backend (API)**: [http://localhost:8000/docs](http://localhost:8000/docs) (Interactive Documentation)

### ✅ How to verify it works

1.  **Check containers**:
    Open another terminal and run:
    ```powershell
    docker ps
    ```
    You should see two active containers: `ml-threat-frontend` and `ml-threat-backend`.

2.  **Connection Test**:
    - Go to [http://localhost:3000](http://localhost:3000).
    - You should see the Dashboard loaded.
    - If you see "System Status" with green indicators (or loading), the connection to the backend is successful.

3.  **Analysis Test**:
    - In the Dashboard, try starting a scan (note: the real proxy requires additional browser configuration, but starting the scan verifies communication).

### 🛑 Stop the application
Press `Ctrl+C` in the terminal where Docker is running, or execute:
```powershell
docker-compose down
```

---

## 🛠️ Manual Configuration (Local Development without Docker)

If you prefer to run it manually or for development:

### 1. Backend
```powershell
cd backend
# Create virtual environment (if it doesn't exist)
python -m venv venv
# Activate
.\venv\Scripts\Activate.ps1
# Install dependencies
pip install -r requirements.txt
# Run
uvicorn main:app --reload
```

### 2. Frontend
```powershell
cd frontend/ml-threat-dashboard
# Install dependencies
npm install
# Run
npm start
```
The frontend will run at `http://localhost:3000` and automatically connect to the backend at `http://localhost:8000`.
