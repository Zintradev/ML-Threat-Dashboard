import os
import logging
import joblib
from typing import Dict, Any, Optional

from app.core.config import MITRE_MAPPING, WHITELIST_DOMAINS
from app.services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

class MLService:
    def __init__(self):
        self.pipeline = self._load_model()
        self.limiter = RateLimiter()

    def _load_model(self) -> Any:
        paths = ["ml_pipeline.pkl", "../backend/ml_pipeline.pkl", "./backend/ml_pipeline.pkl", "/app/ml_pipeline.pkl"]
        for path in paths:
            if os.path.exists(path):
                try:
                    model = joblib.load(path)
                    logger.info(f"NLP Pipeline successfully loaded from {path}")
                    return model
                except Exception as e:
                    logger.error(f"Failed to load NLP Pipeline from {path}: {e}")
        logger.error("NLP Pipeline not found! System will fail-fast on inference.")
        return None

    def reconstruct_request(self, req: Dict[str, Any]) -> str:
        method = req.get('method', 'GET').upper()
        path = req.get('path', '/')
        query_params = req.get('query_params', {})
        
        # Reconstruct query string
        if query_params:
            query_string = "&".join([f"{k}={v}" for k, v in query_params.items()])
            full_path = f"{path}?{query_string}"
        else:
            full_path = path
            
        return f"{method} {full_path} HTTP/1.1"

    def analyze(self, req: Dict[str, Any]) -> Dict[str, Any]:
        host = str(req.get('host', ''))
        src_ip = str(req.get('src_ip', 'unknown'))

        if any(domain in host for domain in WHITELIST_DOMAINS):
            return self._build_result(0, 1.0, "Normal", False)

        if not self.limiter.is_allowed(src_ip):
            return self._build_result(4, 0.99, "DoS", False)

        if not self.pipeline:
            raise RuntimeError("NLP Pipeline not loaded. Cannot perform inference.")

        # Reconstruct and Predict
        raw_http = self.reconstruct_request(req)
        
        try:
            prediction_label = self.pipeline.predict([raw_http])[0]
            prob = float(max(self.pipeline.predict_proba([raw_http])[0]))
            
            attack_mapping = {
                'Normal': (0, 'Normal'),
                'SQL Injection': (1, 'SQL Injection'),
                'XSS': (2, 'XSS'),
                'Path Traversal': (3, 'Path Traversal')
            }
            
            pred_code, att_type = attack_mapping.get(prediction_label, (0, 'Normal'))
            return self._build_result(pred_code, prob, att_type, True)
            
        except Exception as e:
            logger.error(f"Fail-Fast triggered: Exception during ML inference: {e}")
            raise

    def _build_result(self, prediction: int, confidence: float, attack_type: str, is_ml: bool) -> Dict[str, Any]:
        result = {
            "prediction": prediction,
            "confidence": confidence,
            "attack_type": attack_type,
            "real_ml": is_ml,
            "success": True
        }
        if attack_type in MITRE_MAPPING:
            result["mitre_id"] = MITRE_MAPPING[attack_type]
        return result
