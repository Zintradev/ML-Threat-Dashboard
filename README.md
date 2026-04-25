# ML Threat Dashboard 🛡️

ML-powered threat detection dashboard with real-time network traffic analysis using Machine Learning.

## 📋 Description

Threat detection system that analyzes HTTP/HTTPS network traffic in real-time, classifies attacks using ML, and maps detected threats to the MITRE ATT&CK framework.

### Features

- ✅ Real-time threat detection using Machine Learning
- ✅ HTTP/HTTPS traffic analysis with MITMProxy
- ✅ Attack classification (DDoS, SQL Injection, XSS, etc.)
- ✅ MITRE ATT&CK Framework mapping
- ✅ Interactive dashboard with React and TypeScript
- ✅ REST API with FastAPI
- ✅ Dockerized for easy deployment

## 🚀 Quick Start with Docker (Recommended)

### Prerequisites
- [Docker](https://www.docker.com/products/docker-desktop/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Execution

```bash
# Clone repository
git clone https://github.com/Zintradev/ML-Threat-Dashboard.git
cd ML-Threat-Dashboard

# Run with Docker Compose
docker-compose up --build
```

**Access:**
- 🌐 Frontend: http://localhost:3000
- 🔧 Backend API: http://localhost:8000
- 📚 API Docs: http://localhost:8000/docs

### Stop services

```bash
docker-compose down
```

## 🛠️ Local Development (Without Docker)

### Backend

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python main.py
```

Backend available at: http://localhost:8000

### Frontend

```bash
cd frontend/ml-threat-dashboard

# Install dependencies
npm install

# Run in development mode
npm start
```

Frontend available at: http://localhost:3000

## 📊 Technologies

### Backend
- **Python 3.11**
- **FastAPI** - Modern and fast web framework
- **scikit-learn** - Machine Learning
- **MITMProxy** - Traffic interception
- **joblib** - Model serialization

### Frontend
- **React 18** with TypeScript
- **CSS3** with modern design

### Machine Learning
- **Algorithm**: Random Forest Classifier
- **Dataset**: NSL-KDD (Network Security Dataset)
- **Features**: HTTP/HTTPS traffic pattern analysis

### DevOps
- **Docker** - Containerization
- **Docker Compose** - Orchestration
- **Nginx** - Web server for frontend

## 📁 Project Structure

```
ML-Threat-Dashboard/
├── backend/                    # FastAPI Backend
│   ├── main.py                # Main server
│   ├── train_model.py         # Training (synthetic data)
│   ├── train_with_nsl_kdd.py  # Training (real NSL-KDD data)
│   ├── generate_attacks.py    # Simulated attack generator
│   ├── mitmproxy_addon.py     # MITMProxy Addon
│   ├── requirements.txt       # Python dependencies
│   ├── real_traffic_model.pkl # Trained ML model
│   └── *.pkl                  # Encoders and scalers
├── frontend/                   # React Frontend
│   └── ml-threat-dashboard/
│       ├── src/
│       ├── public/
│       └── package.json
├── data/                       # Datasets
│   └── NSL_KDD-master/        # NSL-KDD Dataset
├── notebooks/                  # Jupyter notebooks
│   └── exploratory_analysis.ipynb
├── Dockerfile.backend          # Backend Dockerfile
├── Dockerfile.frontend         # Frontend Dockerfile
├── docker-compose.yml          # Docker Orchestration
├── nginx.conf                  # Nginx Configuration
├── .dockerignore              # Docker excluded files
├── .gitignore                 # Git excluded files
└── README.md                  # This file
```

## 🔧 Configuration

### Environment Variables

You can configure the following variables in `docker-compose.yml`:

```yaml
environment:
  - PYTHONUNBUFFERED=1
  - LOG_LEVEL=INFO
```

### ML Models

The project includes the following pre-trained models:
- `real_traffic_model.pkl` - Main classification model
- `label_encoder_y.pkl` - Label encoder
- `label_encoders.pkl` - Feature encoders
- `scaler.pkl` - Scaler for normalization

## 📈 Usage

### 1. Start the System

```bash
docker-compose up -d
```

### 2. Generate Test Traffic

```bash
# From backend directory
python generate_attacks.py
```

### 3. View Detections in Dashboard

Open http://localhost:3000 and watch real-time detections.

### 4. API Endpoints

- `GET /` - System status
- `GET /status` - Detailed status with statistics
- `POST /scan` - Start scan
- `POST /capture` - Capture request
- `GET /results` - Get analysis results
- `POST /stop` - Stop scan

## 🧪 Testing

### Backend

```bash
cd backend
pytest
```

### Frontend

```bash
cd frontend/ml-threat-dashboard
npm test
```

## 📝 Important Notes

- The virtual environment (`ml_threat_dashboard/`) is excluded from the repository
- Large unused models were removed to optimize size
- The project uses `.gitignore` and `.dockerignore` to keep the repo clean
- For production, consider using environment variables for sensitive configuration

## 🤝 Contributions
This project is primarily for educational purposes. While the code is proprietary, suggestions and improvements for learning purposes are welcome.

If you wish to contribute:

- Fork the project

- Create a branch (git checkout -b feature/Improvement)

- Commit your changes (git commit -m 'Add some Improvement')

- Push to the branch (git push origin feature/Improvement)

- Open a Pull Request

## 📄 License
Copyright © 2025 Zintra. All Rights Reserved.

This project is proprietary software.

✅ Permitted: Permission is granted to view, download, and execute this code for purely educational and personal learning purposes.

❌ Prohibited: Commercial use, redistribution, and modification of this code for public projects or products are not allowed without the explicit permission of the author.

## 👤 Author

**Zintradev**
- GitHub: [@Zintradev](https://github.com/Zintradev)

## 🙏 Acknowledgements

- NSL-KDD Dataset for providing training data
- MITRE ATT&CK Framework for threat taxonomy
- FastAPI and React communities for excellent tools

---

⭐ If you found this project useful, consider giving it a star on GitHub!
