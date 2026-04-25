from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import joblib
import pandas as pd
import numpy as np
import logging
from datetime import datetime, timedelta
import time
import subprocess
import re
from collections import defaultdict, deque
import sys
import os

# Console encoding fix for Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("backend.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# FastAPI App
app = FastAPI(title="ML Threat Detection Dashboard")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MITRE ATT&CK Mapping
MITRE_MAPPING = {
    "SQL Injection": "T1190",
    "XSS": "T1059",
    "Path Traversal": "T1006",
    "DoS": "T1498",
    "Suspicious Activity": "T1071"
}

# Whitelist of safe domains
WHITELIST_DOMAINS = [
    "googleapis.com",
    "gvt1.com",
    "google.com",
    "gstatic.com",
    "microsoft.com",
    "windowsupdate.com",
    "github.com"
]

class RateLimiter:
    def __init__(self, max_requests: int = 50, time_window: int = 10):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(deque)

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        queue = self.requests[ip]
        
        # Remove old requests
        while queue and queue[0] < now - self.time_window:
            queue.popleft()
            
        if len(queue) >= self.max_requests:
            return False
            
        queue.append(now)
        return True

# Rate Limiter Instance
rate_limiter = RateLimiter(max_requests=50, time_window=10)

class RealTimeMLModel:
    def __init__(self):
        self.model = None
        self.rate_limiter = rate_limiter
        self.load_model()

    def load_model(self):
        """Load trained model"""
        try:
            # Try multiple paths for flexibility (local dev and Docker)
            possible_paths = [
                "real_traffic_model.pkl",  # Docker/production
                "../backend/real_traffic_model.pkl",  # Local development
                "./backend/real_traffic_model.pkl"
            ]
            
            model_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    model_path = path
                    break
            
            if model_path:
                model_data = joblib.load(model_path)
                self.model = model_data
                logger.info(f"✅ Real-time ML model loaded from: {model_path}")
            else:
                logger.warning("⚠️ Model file not found. Running in rule-based mode only.")
                logger.info("💡 To use ML model, ensure 'real_traffic_model.pkl' is in the backend directory")
                self.model = None
        except Exception as e:
            logger.error(f"❌ Failed to load model: {e}")
            self.model = None

    def analyze_request(self, request_data: Dict) -> Dict:
        """Analyze request in real-time"""
        src_ip = request_data.get('src_ip', 'unknown')
        host = request_data.get('host', '')
        
        # 0. Whitelist Check
        if any(domain in host for domain in WHITELIST_DOMAINS):
             return {"prediction": 0, "confidence": 1.0, "attack_type": "Normal", "real_ml": False, "success": True, "details": "Whitelisted domain"}

        # 1. Rate Limiting (DoS Detection)
        if not self.rate_limiter.is_allowed(src_ip):
            return {
                "prediction": 4, 
                "confidence": 0.99, 
                "attack_type": "DoS", 
                "mitre_id": MITRE_MAPPING["DoS"],
                "real_ml": False, 
                "success": True,
                "details": "Rate limit exceeded"
            }

        # 2. ML Analysis
        if self.model:
            try:
                result = self.model.predict_http_traffic(request_data)
                # Add MITRE ID
                attack_type = result.get("attack_type", "Normal")
                if attack_type in MITRE_MAPPING:
                    result["mitre_id"] = MITRE_MAPPING[attack_type]
                return result
            except Exception as e:
                # If prediction fails, fallback to rules
                pass
        
        # 3. Fallback to rules
        return self._rule_based_analysis(request_data)
    
    def _rule_based_analysis(self, request_data: Dict) -> Dict:
        """Rule-based analysis"""
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        path = request_data.get('path', '')
        query_params = request_data.get('query_params', {})
        
        full_url = (url + path).lower()
        
        # SQL Injection Detection
        sql_patterns = [r"'.*?(union|select|insert|update|delete|drop|exec).*?'",
                       r"'.*?(\-\-|#|\/\*).*?'", r"'.*?(1=1|2=2|0=0).*?'"]
        if any(re.search(pattern, full_url, re.IGNORECASE) for pattern in sql_patterns):
            return {"prediction": 1, "confidence": 0.90, "attack_type": "SQL Injection", "mitre_id": MITRE_MAPPING["SQL Injection"], "real_ml": False, "success": True}
        
        # XSS Detection
        xss_patterns = [r"<script.*?>.*?</script>", r"javascript:", r"onload=.*?", r"alert\(.*?\)"]
        if any(re.search(pattern, full_url, re.IGNORECASE) for pattern in xss_patterns):
            return {"prediction": 2, "confidence": 0.85, "attack_type": "XSS", "mitre_id": MITRE_MAPPING["XSS"], "real_ml": False, "success": True}
        
        # Path Traversal Detection
        traversal_patterns = [r"\.\.\/\.\.\/", r"\.\.\\\.\.\\", r"etc/passwd", r"win\.ini"]
        if any(re.search(pattern, full_url, re.IGNORECASE) for pattern in traversal_patterns):
            return {"prediction": 3, "confidence": 0.80, "attack_type": "Path Traversal", "mitre_id": MITRE_MAPPING["Path Traversal"], "real_ml": False, "success": True}
        
        # Suspicious Activity Detection
        if len(path) > 100 or any(len(str(v)) > 50 for v in query_params.values()):
            return {"prediction": 4, "confidence": 0.70, "attack_type": "Suspicious Activity", "mitre_id": MITRE_MAPPING["Suspicious Activity"], "real_ml": False, "success": True}
        
        return {"prediction": 0, "confidence": 0.95, "attack_type": "Normal", "real_ml": False, "success": True}

class TrafficCaptureSystem:
    def __init__(self):
        self.traffic_data = []
        self.ml_model = RealTimeMLModel()
        self.proxy_process = None
        self.is_running = False
        self.request_count = 0
        self.start_time = datetime.now()
        self.unique_ips = set()
        self.unique_hosts = set()
        self.threat_count = 0
    
    def start_proxy(self):
        """Start MITMProxy"""
        try:
            self.stop_proxy()
            
            self.proxy_process = subprocess.Popen([
                "mitmdump", 
                "-p", "8080",
                "--set", "listen_host=127.0.0.1",
                "-s", "mitmproxy_addon.py",
                "-q"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            time.sleep(3)
            
            # Check if process is actually running
            if self.proxy_process.poll() is None:
                self.is_running = True
                logger.info("🎯 MITMProxy started successfully!")
                return True
            else:
                self.is_running = False
                logger.error("❌ MITMProxy failed to start")
                return False
                
        except Exception as e:
            self.is_running = False
            logger.error(f"❌ Failed to start MITMProxy: {e}")
            return False
    
    def process_traffic(self, request_data: Dict):
        """Process incoming traffic"""
        self.request_count += 1
        
        # ML Analysis
        ml_result = self.ml_model.analyze_request(request_data)
        
        # Statistics
        self.unique_ips.add(request_data.get('src_ip', 'unknown'))
        self.unique_hosts.add(request_data.get('host', 'unknown'))
        if ml_result["prediction"] != 0:
            self.threat_count += 1
        
        # Create entry
        entry = {
            "timestamp": datetime.fromtimestamp(request_data.get('timestamp', time.time())).isoformat(),
            "url": request_data.get('url', ''),
            "method": request_data.get('method', 'GET'),
            "src_ip": request_data.get('src_ip', 'unknown'),
            "host": request_data.get('host', ''),
            "path": request_data.get('path', ''),
            "ml_analysis": ml_result,
            "is_threat": ml_result["prediction"] != 0,
            "data_source": "REAL_TRAFFIC",
            "request_id": self.request_count
        }
        
        self.traffic_data.append(entry)
        
        # Log
        status = "🚨 THREAT" if entry["is_threat"] else "✅ NORMAL"
        logger.info(f"📡 #{self.request_count}: {entry['method']} {entry['host']}{entry['path']} → {status}")
        
        return entry
    
    def stop_proxy(self):
        """Stop MITMProxy"""
        if self.proxy_process:
            self.proxy_process.terminate()
            try:
                self.proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proxy_process.kill()
            self.proxy_process = None
        self.is_running = False
        logger.info("🛑 MITMProxy stopped")
    
    def get_recent_data(self, count: int = 50):
        return self.traffic_data[-count:]
    
    def get_stats(self):
        recent = self.traffic_data[-100:]
        threats = [r for r in recent if r['is_threat']]
        capture_duration = datetime.now() - self.start_time
        
        return {
            "total_requests": len(self.traffic_data),
            "threats_detected": self.threat_count,
            "unique_ips": len(self.unique_ips),
            "unique_hosts": len(self.unique_hosts),
            "proxy_running": self.is_running,
            "capture_duration": str(capture_duration).split('.')[0],
            "data_source": "REAL_TRAFFIC",
            "model_loaded": self.ml_model.model is not None
        }

# Global Instance
traffic_capture = TrafficCaptureSystem()

# Pydantic Models
class ScanRequest(BaseModel):
    target_url: str

class TrafficCaptureRequest(BaseModel):
    timestamp: float
    url: str
    method: str
    src_ip: str
    host: Optional[str] = None
    path: Optional[str] = None
    headers: Optional[Dict] = None
    content_length: Optional[int] = 0
    query_params: Optional[Dict] = None
    status_code: Optional[int] = 200

# Endpoints
@app.get("/")
async def root():
    return {
        "message": "Real Traffic ML Detection v2.2", 
        "status": "operational", 
        "model_loaded": traffic_capture.ml_model.model is not None
    }

@app.get("/system/status")
async def get_system_status():
    """Get system status for frontend"""
    return {
        "system": {
            "status": "operational",
            "mode": "live",
            "proxy_active": traffic_capture.is_running
        },
        "components": {
            "ml_model": {
                "status": "loaded" if traffic_capture.ml_model.model else "fallback",
                "real_model": traffic_capture.ml_model.model is not None
            },
            "mitmproxy": {
                "status": "running" if traffic_capture.is_running else "stopped",
                "port": 8080
            },
            "traffic_capture": {
                "status": "active" if traffic_capture.is_running else "idle",
                "data_source": "REAL_TRAFFIC"
            }
        }
    }

@app.post("/scan/start")
async def start_scan(request: ScanRequest):
    success = traffic_capture.start_proxy()
    return {
        "status": "started" if success else "failed",
        "message": "MITMProxy started" if success else "Failed to start MITMProxy",
        "proxy_port": 8080
    }

@app.post("/capture/request")
async def capture_request(request_data: TrafficCaptureRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(traffic_capture.process_traffic, request_data.dict())
    return {"status": "captured", "request_id": traffic_capture.request_count + 1}

@app.get("/analysis/results")
async def get_analysis_results():
    data = traffic_capture.get_recent_data(50)
    stats = traffic_capture.get_stats()
    
    return {
        "stats": stats,
        "analysis_results": data,
        "proxy_status": "running" if traffic_capture.is_running else "stopped"
    }

@app.post("/scan/stop")
async def stop_scan():
    traffic_capture.stop_proxy()
    return {"status": "stopped", "message": "MITMProxy stopped"}

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Real Traffic ML Detection...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
