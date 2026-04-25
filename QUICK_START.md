# 🚀 QUICK START GUIDE

## 📋 Prerequisites
- **Docker** (optional, recommended for quick deployment)
- **Python 3.9+** and virtual environment
- **Node.js** (for the frontend)

## 🛠️ Backend (Already Fixed)
The `backend/main.py` file is fixed and ready to run. You don't need to make manual changes.

## 🐳 Option 1: Run with Docker (Recommended)
```powershell
# From the project root
docker-compose up --build
```
- **Frontend:** http://localhost:3000
- **Backend:** http://localhost:8000

## 💻 Option 2: Run Locally
### Backend
```powershell
cd backend
# Activate virtual environment (adjust path if necessary)
.\ml_threat_dashboard\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```
### Frontend
```powershell
cd frontend/ml-threat-dashboard
npm install
npm start
```

## ✅ Verify it works
1. **Backend**: Navigate to `http://localhost:8000` and you should see:
   ```json
   {"message":"Real Traffic ML Detection v2.2","status":"operational"}
   ```
2. **Frontend**: Open `http://localhost:3000` and the dashboard should load.
3. **API Documentation**: `http://localhost:8000/docs` shows the interactive UI.

## 🔮 Next Steps
- Train the model with real data: `python backend/train_model.py`
- Explore the API and customize rules.

## 🛠️ Troubleshooting
- **Model file not found**: Run the training script to generate `real_traffic_model.pkl`.
- **Port 3000 already in use**: Change the port in `docker-compose.yml` or free up the port.
- **Docker not installed**: Install Docker Desktop from https://www.docker.com/products/docker-desktop/
