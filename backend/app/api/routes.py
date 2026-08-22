from fastapi import APIRouter, BackgroundTasks, Depends
from datetime import datetime
from collections import deque
from typing import Dict, Any, List

from app.models.schemas import ScanRequest, TrafficRequest
from app.services.ml_service import MLService
from app.services.proxy_service import ProxyService

router = APIRouter()

# Global state to maintain simplicity akin to the original monolith
class SystemState:
    def __init__(self):
        self.data = deque(maxlen=10000)
        self.analyzer = MLService()
        self.proxy_service = ProxyService()
        self.stats = {
            "requests": 0, 
            "threats": 0, 
            "ips": set(), 
            "hosts": set(), 
            "start": datetime.now()
        }

    def process(self, req: Dict[str, Any]) -> None:
        self.stats["requests"] += 1
        self.stats["ips"].add(req.get('src_ip', 'unknown'))
        self.stats["hosts"].add(req.get('host', 'unknown'))
        
        res = self.analyzer.analyze(req)
        is_threat = res["prediction"] != 0
        
        if is_threat: 
            self.stats["threats"] += 1
            
        # Ensure timestamp is parsed properly or fallback to isoformat string
        ts = req.get('timestamp')
        if ts:
            ts_iso = datetime.fromtimestamp(ts).isoformat()
        else:
            ts_iso = datetime.now().isoformat()

        self.data.append({
            "timestamp": ts_iso,
            "url": req.get('url', ''),
            "method": req.get('method', 'GET'),
            "src_ip": req.get('src_ip', 'unknown'),
            "host": req.get('host', ''),
            "path": req.get('path', ''),
            "ml_analysis": res,
            "is_threat": is_threat
        })

state = SystemState()

def get_system_state() -> SystemState:
    return state

@router.get("/system/status")
def status(sys: SystemState = Depends(get_system_state)):
    return {
        "system": {
            "status": "operational", 
            "mode": "live", 
            "proxy_active": sys.proxy_service.is_running()
        },
        "components": {
            "ml_model": {
                "status": "loaded" if sys.analyzer.pipeline else "fallback", 
                "real_model": sys.analyzer.pipeline is not None
            },
            "mitmproxy": {
                "status": "running" if sys.proxy_service.is_running() else "stopped", 
                "port": 8080
            }
        }
    }

@router.post("/scan/start")
def start_scan(req: ScanRequest, sys: SystemState = Depends(get_system_state)):
    success = sys.proxy_service.start()
    return {"status": "started" if success else "failed"}

@router.post("/scan/stop")
def stop_scan(sys: SystemState = Depends(get_system_state)):
    sys.proxy_service.stop()
    return {"status": "stopped"}

@router.post("/capture/request")
def capture(req: TrafficRequest, bg: BackgroundTasks, sys: SystemState = Depends(get_system_state)):
    req_dict = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    bg.add_task(sys.process, req_dict)
    return {"status": "captured"}

@router.get("/analysis/results")
def results(sys: SystemState = Depends(get_system_state)):
    duration = str(datetime.now() - sys.stats["start"]).split('.')[0]
    return {
        "stats": {
            "total_requests": sys.stats["requests"],
            "threats_detected": sys.stats["threats"],
            "unique_ips": len(sys.stats["ips"]),
            "unique_hosts": len(sys.stats["hosts"]),
            "proxy_running": sys.proxy_service.is_running(),
            "capture_duration": duration,
            "data_source": "REAL_TRAFFIC"
        },
        "analysis_results": list(sys.data),
        "proxy_status": "running" if sys.proxy_service.is_running() else "stopped"
    }
