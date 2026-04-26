import sys, os, time, subprocess, re, logging, joblib
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Optional
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

app = FastAPI(title="ML Threat Detection Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

MITRE_MAPPING = {"SQL Injection": "T1190", "XSS": "T1059", "Path Traversal": "T1006", "DoS": "T1498"}
WHITELIST = ["googleapis.com", "google.com", "microsoft.com", "github.com"]

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(deque)

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        q = self.requests[ip]
        while q and q[0] < now - 10: q.popleft()
        if len(q) >= 50: return False
        q.append(now)
        return True

class MLModel:
    def __init__(self):
        self.model = self._load()
        self.limiter = RateLimiter()

    def _load(self):
        paths = ["real_traffic_model.pkl", "../backend/real_traffic_model.pkl", "./backend/real_traffic_model.pkl"]
        return next((joblib.load(p) for p in paths if os.path.exists(p)), None)

    def analyze(self, req: Dict) -> Dict:
        if any(d in req.get('host', '') for d in WHITELIST):
            return {"prediction": 0, "confidence": 1.0, "attack_type": "Normal", "real_ml": False, "success": True}

        if not self.limiter.is_allowed(req.get('src_ip', 'unknown')):
            return {"prediction": 4, "confidence": 0.99, "attack_type": "DoS", "mitre_id": "T1498", "real_ml": False, "success": True}

        if self.model:
            try:
                res = self.model.predict_http_traffic(req)
                if res.get("attack_type") in MITRE_MAPPING: res["mitre_id"] = MITRE_MAPPING[res["attack_type"]]
                return res
            except: pass

        url = (req.get('url', '') + req.get('path', '')).lower()
        if any(re.search(p, url) for p in [r"(union|select|insert|delete|drop)", r"(\-\-|#|\/\*)"]):
            return {"prediction": 1, "confidence": 0.90, "attack_type": "SQL Injection", "mitre_id": "T1190", "real_ml": False, "success": True}
        if any(re.search(p, url) for p in [r"<script", r"javascript:", r"onload="]):
            return {"prediction": 2, "confidence": 0.85, "attack_type": "XSS", "mitre_id": "T1059", "real_ml": False, "success": True}
        if any(re.search(p, url) for p in [r"\.\.\/", r"etc/passwd"]):
            return {"prediction": 3, "confidence": 0.80, "attack_type": "Path Traversal", "mitre_id": "T1006", "real_ml": False, "success": True}

        return {"prediction": 0, "confidence": 0.95, "attack_type": "Normal", "real_ml": False, "success": True}

class TrafficSystem:
    def __init__(self):
        self.data = deque(maxlen=10000)
        self.analyzer = MLModel()
        self.proxy = None
        self.stats = {"requests": 0, "threats": 0, "ips": set(), "hosts": set(), "start": datetime.now()}

    def start(self):
        if self.proxy: self.proxy.terminate()
        self.proxy = subprocess.Popen(["mitmdump", "-p", "8080", "--set", "listen_host=127.0.0.1", "-s", "mitmproxy_addon.py", "-q"])
        time.sleep(2)
        return self.proxy.poll() is None

    def stop(self):
        if self.proxy:
            self.proxy.terminate()
            self.proxy = None

    def process(self, req: Dict):
        self.stats["requests"] += 1
        self.stats["ips"].add(req.get('src_ip', 'unknown'))
        self.stats["hosts"].add(req.get('host', 'unknown'))

        res = self.analyzer.analyze(req)
        is_threat = res["prediction"] != 0
        if is_threat: self.stats["threats"] += 1

        self.data.append({
            "timestamp": datetime.fromtimestamp(req.get('timestamp', time.time())).isoformat(),
            "url": req.get('url', ''),
            "method": req.get('method', 'GET'),
            "src_ip": req.get('src_ip', 'unknown'),
            "host": req.get('host', ''),
            "path": req.get('path', ''),
            "ml_analysis": res,
            "is_threat": is_threat
        })

system = TrafficSystem()

class ScanRequest(BaseModel): target_url: str
class TrafficRequest(BaseModel):
    timestamp: float
    url: str
    method: str
    src_ip: str
    host: Optional[str] = None
    path: Optional[str] = None

@app.get("/system/status")
def status():
    return {
        "system": {"status": "operational", "mode": "live", "proxy_active": system.proxy is not None},
        "components": {
            "ml_model": {"status": "loaded" if system.analyzer.model else "fallback", "real_model": system.analyzer.model is not None},
            "mitmproxy": {"status": "running" if system.proxy else "stopped", "port": 8080}
        }
    }

@app.post("/scan/start")
def start_scan(req: ScanRequest):
    return {"status": "started" if system.start() else "failed"}

@app.post("/scan/stop")
def stop_scan():
    system.stop()
    return {"status": "stopped"}

@app.post("/capture/request")
def capture(req: TrafficRequest, bg: BackgroundTasks):
    bg.add_task(system.process, req.dict())
    return {"status": "captured"}

@app.get("/analysis/results")
def results():
    return {
        "stats": {
            "total_requests": system.stats["requests"],
            "threats_detected": system.stats["threats"],
            "unique_ips": len(system.stats["ips"]),
            "unique_hosts": len(system.stats["hosts"]),
            "proxy_running": system.proxy is not None,
            "capture_duration": str(datetime.now() - system.stats["start"]).split('.')[0],
            "data_source": "REAL_TRAFFIC"
        },
        "analysis_results": list(system.data)[-50:],
        "proxy_status": "running" if system.proxy else "stopped"
    }
