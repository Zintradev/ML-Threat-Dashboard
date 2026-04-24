from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import joblib
import pandas as pd
import numpy as np
import logging
from datetime import datetime
import time
import subprocess
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Real Traffic ML Detection", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"], allow_methods=["*"], allow_headers=["*"])

class RealTimeMLModel:
    def __init__(self):
        self.model = None
        self.load_model()
    
    def load_model(self):
        """Cargar modelo entrenado"""
        try:
            model_data = joblib.load("../backend/real_traffic_model.pkl")
            self.model = model_data
            logger.info("✅ Real-time ML model loaded successfully!")
        except Exception as e:
            logger.error(f"❌ Failed to load model: {e}")
            self.model = None
    
    def analyze_request(self, request_data: Dict) -> Dict:
        """Analizar request en tiempo real"""
        if self.model:
            try:
                # Usar el modelo entrenado
                result = self.model.predict_http_traffic(request_data)
                return result
            except Exception as e:
                logger.error(f"❌ ML analysis error: {e}")
        
        # Fallback a detección por reglas
        return self._rule_based_analysis(request_data)
    
    def _rule_based_analysis(self, request_data: Dict) -> Dict:
        """Análisis basado en reglas"""
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        path = request_data.get('path', '')
        query_params = request_data.get('query_params', {})
        
        full_url = (url + path).lower()
        
        # Detección de SQL Injection
        sql_patterns = [r"'.*?(union|select|insert|update|delete|drop|exec).*?'",
                       r"'.*?(\-\-|#|\/\*).*?'", r"'.*?(1=1|2=2|0=0).*?'"]
        if any(re.search(pattern, full_url, re.IGNORECASE) for pattern in sql_patterns):
            return {"prediction": 1, "confidence": 0.90, "attack_type": "SQL Injection", "real_ml": False, "success": True}
        
        # Detección de XSS
        xss_patterns = [r"<script.*?>.*?</script>", r"javascript:", r"onload=.*?", r"alert\(.*?\)"]
        if any(re.search(pattern, full_url, re.IGNORECASE) for pattern in xss_patterns):
            return {"prediction": 2, "confidence": 0.85, "attack_type": "XSS", "real_ml": False, "success": True}
        
        # Detección de Path Traversal
        traversal_patterns = [r"\.\.\/\.\.\/", r"\.\.\\\.\.\\", r"etc/passwd", r"win\.ini"]
        if any(re.search(pattern, full_url, re.IGNORECASE) for pattern in traversal_patterns):
            return {"prediction": 3, "confidence": 0.80, "attack_type": "Path Traversal", "real_ml": False, "success": True}
        
        # Detección de actividad sospechosa
        if len(path) > 100 or any(len(str(v)) > 50 for v in query_params.values()):
            return {"prediction": 4, "confidence": 0.70, "attack_type": "Suspicious Activity", "real_ml": False, "success": True}
        
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
        """Iniciar MITMProxy"""
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
            
            if self.proxy_process.poll() is None:
                self.is_running = True
                logger.info("🎯 MITMProxy started successfully!")
                return True
            else:
                logger.error("❌ MITMProxy failed to start")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to start MITMProxy: {e}")
            return False
    
    def process_traffic(self, request_data: Dict):
        """Procesar tráfico entrante"""
        self.request_count += 1
        
        # Análisis ML
        ml_result = self.ml_model.analyze_request(request_data)
        
        # Estadísticas
        self.unique_ips.add(request_data.get('src_ip', 'unknown'))
        self.unique_hosts.add(request_data.get('host', 'unknown'))
        if ml_result["prediction"] != 0:
            self.threat_count += 1
        
        # Crear entrada
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
        """Detener MITMProxy"""
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

# Instancia global
traffic_capture = TrafficCaptureSystem()

# Modelos Pydantic
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
        "message": "Real Traffic ML Detection v2.0", 
        "status": "operational", 
        "model_loaded": traffic_capture.ml_model.model is not None
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