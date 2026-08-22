from fastapi import APIRouter, BackgroundTasks, Depends
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.schemas import ScanRequest, TrafficRequest
from app.services.ml_service import MLService
from app.services.proxy_service import ProxyService
from app.db.database import get_db, SessionLocal
from app.db.models import TrafficLog

router = APIRouter()

# Global state to maintain simplicity akin to the original monolith
class SystemState:
    def __init__(self):
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
            
        # Ensure timestamp is parsed properly or fallback to utcnow
        ts = req.get('timestamp')
        if ts:
            ts_dt = datetime.fromtimestamp(ts)
        else:
            ts_dt = datetime.utcnow()

        db = SessionLocal()
        try:
            log_entry = TrafficLog(
                timestamp=ts_dt,
                method=req.get('method', 'GET'),
                url=req.get('url', ''),
                source_ip=req.get('src_ip', 'unknown'),
                attack_type=res.get("attack_type", "Normal"),
                confidence=res.get("confidence", 1.0),
                mitre_id=res.get("mitre_id")
            )
            db.add(log_entry)
            db.commit()
        finally:
            db.close()

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
def results(sys: SystemState = Depends(get_system_state), db: Session = Depends(get_db)):
    duration = str(datetime.now() - sys.stats["start"]).split('.')[0]
    
    logs = db.query(TrafficLog).order_by(TrafficLog.timestamp.desc()).limit(1000).all()
    
    formatted_logs = []
    pred_map = {'Normal': 0, 'SQL Injection': 1, 'XSS': 2, 'Path Traversal': 3}
    
    for log in logs:
        is_threat = log.attack_type != "Normal"
        pred_code = pred_map.get(log.attack_type, 1 if is_threat else 0)
        
        res = {
            "prediction": pred_code,
            "confidence": log.confidence,
            "attack_type": log.attack_type,
            "real_ml": True,
            "success": True
        }
        if log.mitre_id:
            res["mitre_id"] = log.mitre_id
            
        formatted_logs.append({
            "timestamp": log.timestamp.isoformat(),
            "url": log.url,
            "method": log.method,
            "src_ip": log.source_ip,
            "host": log.url.split('/')[2] if '//' in log.url else "",
            "path": '/' + '/'.join(log.url.split('/')[3:]) if '//' in log.url else log.url,
            "ml_analysis": res,
            "is_threat": is_threat
        })

    total_req = db.query(TrafficLog).count()
    total_threats = db.query(TrafficLog).filter(TrafficLog.attack_type != "Normal").count()
    unique_ips = db.query(TrafficLog.source_ip).distinct().count()

    return {
        "stats": {
            "total_requests": total_req,
            "threats_detected": total_threats,
            "unique_ips": unique_ips,
            "unique_hosts": len(sys.stats["hosts"]),
            "proxy_running": sys.proxy_service.is_running(),
            "capture_duration": duration,
            "data_source": "REAL_TRAFFIC"
        },
        "analysis_results": formatted_logs,
        "proxy_status": "running" if sys.proxy_service.is_running() else "stopped"
    }
