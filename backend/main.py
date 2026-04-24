# backend/main.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import asyncio
import joblib
import pandas as pd
import numpy as np
import json
import time
import logging
from datetime import datetime
import subprocess
import threading
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import requests

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Real ML Threat Detection API - Hybrid System",
    description="Sistema híbrido real de detección de amenazas con ML, OWASP ZAP y captura de tráfico",
    version="4.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== CONFIGURACIÓN ====================
class Config:
    ZAP_PROXY = "http://127.0.0.1:8080"
    CAPTURE_INTERFACE = "ethernet"  # Cambiar por tu interfaz de red
    ML_MODEL_PATH = "rf_model_nsl_kdd.pkl"
    SCALER_PATH = "scaler.pkl"
    LABEL_ENCODERS_PATH = "label_encoders.pkl"

# ==================== MODELO ML ====================
class MLModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoders = None
        self.is_loaded = False
        self.load_model()
    
    def load_model(self):
        try:
            self.model = joblib.load(Config.ML_MODEL_PATH)
            self.scaler = joblib.load(Config.SCALER_PATH)
            self.label_encoders = joblib.load(Config.LABEL_ENCODERS_PATH)
            self.is_loaded = True
            logger.info("✅ ML Model loaded successfully")
        except Exception as e:
            logger.error(f"❌ Error loading ML model: {e}")
            self.is_loaded = False
    
    def predict(self, features: Dict) -> Dict:
        if not self.is_loaded:
            return self._simulate_prediction()
        
        try:
            # Convertir a DataFrame y preprocesar
            df = pd.DataFrame([features])
            processed_data = self._preprocess_data(df)
            
            # Predecir
            prediction = self.model.predict(processed_data)[0]
            probability = self.model.predict_proba(processed_data)[0]
            confidence = max(probability)
            
            return {
                "prediction": int(prediction),
                "probability": float(confidence),
                "confidence": float(confidence),
                "attack_type": self._get_attack_name(prediction),
                "real_ml": True,
                "success": True
            }
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return self._simulate_prediction()
    
    def _preprocess_data(self, df: pd.DataFrame) -> pd.DataFrame:
        # Implementar preprocesamiento igual que en entrenamiento
        for col, encoder in self.label_encoders.items():
            if col in df.columns:
                df[col] = df[col].apply(lambda x: x if x in encoder.classes_ else encoder.classes_[0])
                df[col] = encoder.transform(df[col])
        return self.scaler.transform(df)
    
    def _get_attack_name(self, prediction: int) -> str:
        attack_types = {
            0: "Normal",
            1: "Denial of Service",
            2: "Probing", 
            3: "Remote to Local",
            4: "User to Root"
        }
        return attack_types.get(prediction, "Unknown")
    
    def _simulate_prediction(self) -> Dict:
        is_attack = random.random() > 0.7
        return {
            "prediction": 1 if is_attack else 0,
            "probability": random.uniform(0.7, 0.95) if is_attack else random.uniform(0.1, 0.4),
            "confidence": random.uniform(0.8, 0.99) if is_attack else random.uniform(0.6, 0.9),
            "attack_type": "Simulated Attack" if is_attack else "Normal",
            "real_ml": False,
            "success": True
        }

# ==================== CAPTURA DE TRÁFICO REAL ====================
class RealTrafficCapture:
    def __init__(self):
        self.traffic_buffer = []
        self.is_capturing = False
        self.packet_count = 0
        self.suspicious_packets = []
    
    def start_capture(self, interface: str):
        """Inicia captura de tráfico real en segundo plano"""
        def capture_loop():
            self.is_capturing = True
            logger.info(f"🚀 Starting real traffic capture on {interface}")
            
            try:
                sniff(iface=interface, prn=self._packet_handler, store=False)
            except Exception as e:
                logger.error(f"Capture error: {e}")
                self.is_capturing = False
        
        thread = threading.Thread(target=capture_loop, daemon=True)
        thread.start()
    
    def _packet_handler(self, packet):
        """Procesa cada paquete de red capturado"""
        if IP in packet:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': self._get_protocol_name(packet),
                'size': len(packet),
                'src_port': packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
                'dst_port': packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0,
                'flags': self._extract_tcp_flags(packet),
                'ttl': packet[IP].ttl
            }
            
            # Detección básica de anomalías
            if self._is_suspicious_packet(packet_info):
                packet_info['suspicious'] = True
                self.suspicious_packets.append(packet_info)
            
            self.traffic_buffer.append(packet_info)
            self.packet_count += 1
            
            # Mantener buffer limitado
            if len(self.traffic_buffer) > 1000:
                self.traffic_buffer = self.traffic_buffer[-500:]
    
    def _get_protocol_name(self, packet) -> str:
        if TCP in packet: return "TCP"
        if UDP in packet: return "UDP"
        if ICMP in packet: return "ICMP"
        return "OTHER"
    
    def _extract_tcp_flags(self, packet) -> str:
        if TCP in packet:
            flags = packet[TCP].flags
            return str(flags)
        return ""
    
    def _is_suspicious_packet(self, packet_info: Dict) -> bool:
        # Detección básica de patrones sospechosos
        if packet_info['ttl'] < 10:  # TTL muy bajo
            return True
        if packet_info['dst_port'] in [22, 23, 3389]:  # Puertos de administración
            return True
        if packet_info['size'] > 1500:  # Paquetes muy grandes
            return True
        return False
    
    def get_recent_traffic(self, count: int = 50) -> List[Dict]:
        return self.traffic_buffer[-count:]
    
    def get_stats(self) -> Dict:
        return {
            "total_packets": self.packet_count,
            "suspicious_packets": len(self.suspicious_packets),
            "is_capturing": self.is_capturing,
            "buffer_size": len(self.traffic_buffer)
        }

# ==================== OWASP ZAP REAL ====================
class RealZAPScanner:
    def __init__(self):
        self.api_key = "your-api-key"
        self.base_url = "http://127.0.0.1:8080"
        self.is_available = self._check_zap_availability()
    
    def _check_zap_availability(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/JSON/core/view/version/", 
                                  proxies={"http": Config.ZAP_PROXY, "https": Config.ZAP_PROXY})
            return response.status_code == 200
        except:
            logger.warning("OWASP ZAP not available - running in simulation mode")
            return False
    
    async def scan_website(self, target_url: str) -> Dict:
        if not self.is_available:
            return await self._simulate_scan(target_url)
        
        try:
            # Spidering
            spider_url = f"{self.base_url}/JSON/spider/action/scan/"
            params = {"url": target_url, "apikey": self.api_key}
            response = requests.post(spider_url, params=params)
            scan_id = response.json().get("scan")
            
            # Esperar spidering
            await asyncio.sleep(10)
            
            # Obtener alertas
            alerts_url = f"{self.base_url}/JSON/core/view/alerts/"
            alerts_response = requests.get(alerts_url, params={"apikey": self.api_key})
            alerts = alerts_response.json().get("alerts", [])
            
            return {
                "real_scan": True,
                "target": target_url,
                "alerts_found": len(alerts),
                "alerts": alerts[:10],  # Limitar a 10 alertas
                "risk_summary": self._analyze_risk(alerts)
            }
            
        except Exception as e:
            logger.error(f"ZAP scan error: {e}")
            return await self._simulate_scan(target_url)
    
    async def _simulate_scan(self, target_url: str) -> Dict:
        """Simulación cuando ZAP no está disponible"""
        await asyncio.sleep(5)  # Simular tiempo de escaneo
        
        vulnerabilities = [
            {"alert": "XSS Vulnerability", "risk": "High", "url": f"{target_url}/login", "description": "Cross-site scripting detected"},
            {"alert": "SQL Injection", "risk": "High", "url": f"{target_url}/search", "description": "SQL injection potential"},
            {"alert": "Missing Security Headers", "risk": "Medium", "url": target_url, "description": "Missing X-Content-Type-Options"}
        ]
        
        return {
            "real_scan": False,
            "target": target_url,
            "alerts_found": len(vulnerabilities),
            "alerts": vulnerabilities,
            "risk_summary": "Medium"
        }
    
    def _analyze_risk(self, alerts: List) -> str:
        if not alerts:
            return "Low"
        
        high_risk = sum(1 for alert in alerts if alert.get('risk') == 'High')
        if high_risk > 0:
            return "High"
        elif sum(1 for alert in alerts if alert.get('risk') == 'Medium') > 0:
            return "Medium"
        return "Low"

# ==================== SISTEMA HÍBRIDO PRINCIPAL ====================
class HybridThreatDetectionSystem:
    def __init__(self):
        self.ml_model = MLModel()
        self.traffic_capture = RealTrafficCapture()
        self.zap_scanner = RealZAPScanner()
        self.detection_history = []
        
        # Iniciar captura de tráfico automáticamente
        self.traffic_capture.start_capture(Config.CAPTURE_INTERFACE)
    
    async def analyze_realtime_traffic(self) -> List[Dict]:
        """Analiza tráfico en tiempo real con ML"""
        recent_traffic = self.traffic_capture.get_recent_traffic(20)
        analysis_results = []
        
        for packet in recent_traffic[-10:]:  # Analizar últimos 10 paquetes
            ml_features = self._convert_to_ml_features(packet)
            ml_result = self.ml_model.predict(ml_features)
            
            result = {
                "packet_info": packet,
                "ml_analysis": ml_result,
                "timestamp": datetime.now().isoformat(),
                "is_threat": ml_result["prediction"] != 0
            }
            
            analysis_results.append(result)
            
            # Guardar en historial si es amenaza
            if result["is_threat"]:
                self.detection_history.append(result)
        
        return analysis_results
    
    def _convert_to_ml_features(self, packet: Dict) -> Dict:
        """Convierte paquete real a características para ML"""
        return {
            'duration': 0.0,
            'protocol_type': 'tcp' if packet['protocol'] == 'TCP' else 'udp',
            'service': self._map_port_to_service(packet['dst_port']),
            'flag': 'SF',  # Simplificado
            'src_bytes': packet['size'],
            'dst_bytes': 0,
            'count': len([p for p in self.traffic_capture.traffic_buffer 
                         if p['src_ip'] == packet['src_ip']]),
            'serror_rate': 0.0,
            'rerror_rate': 0.0,
            'same_srv_rate': 0.0,
            'diff_srv_rate': 0.0,
            'dst_host_count': len(set(p['dst_ip'] for p in self.traffic_capture.traffic_buffer)),
            'dst_host_srv_count': len(set(p['dst_port'] for p in self.traffic_capture.traffic_buffer)),
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_serror_rate': 0.0
        }
    
    def _map_port_to_service(self, port: int) -> str:
        service_map = {
            80: 'http', 443: 'https', 21: 'ftp', 22: 'ssh',
            25: 'smtp', 53: 'dns', 110: 'pop3', 143: 'imap'
        }
        return service_map.get(port, 'other')
    
    async def comprehensive_scan(self, target_url: str) -> Dict:
        """Escaneo completo: OWASP ZAP + Análisis ML"""
        # 1. Escaneo OWASP ZAP
        zap_results = await self.zap_scanner.scan_website(target_url)
        
        # 2. Generar tráfico simulado basado en resultados ZAP
        simulated_traffic = self._generate_traffic_from_scan(zap_results)
        
        # 3. Análisis ML del tráfico simulado
        ml_analysis = self.ml_model.predict(simulated_traffic)
        
        # 4. Combinar resultados
        return {
            "scan_type": "comprehensive",
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "zap_scan": zap_results,
            "ml_analysis": ml_analysis,
            "overall_risk": self._calculate_overall_risk(zap_results, ml_analysis),
            "recommendations": self._generate_recommendations(zap_results, ml_analysis)
        }
    
    def _generate_traffic_from_scan(self, zap_results: Dict) -> Dict:
        """Genera datos de tráfico basados en resultados del escaneo"""
        alerts_count = zap_results.get("alerts_found", 0)
        
        # Más alertas = más características sospechosas
        return {
            'duration': max(1.0, alerts_count * 0.5),
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'S0' if alerts_count > 0 else 'SF',
            'src_bytes': 1000 + (alerts_count * 100),
            'dst_bytes': 500 + (alerts_count * 50),
            'count': 10 + alerts_count,
            'serror_rate': min(0.8, alerts_count * 0.1),
            'rerror_rate': min(0.5, alerts_count * 0.05),
            'same_srv_rate': 0.5,
            'diff_srv_rate': min(0.8, alerts_count * 0.1),
            'dst_host_count': 5 + alerts_count,
            'dst_host_srv_count': 3 + alerts_count,
            'dst_host_same_src_port_rate': 0.1,
            'dst_host_serror_rate': min(0.7, alerts_count * 0.1)
        }
    
    def _calculate_overall_risk(self, zap_results: Dict, ml_analysis: Dict) -> str:
        risk_score = 0
        
        # Riesgo de ZAP
        zap_risk = zap_results.get("risk_summary", "Low")
        if zap_risk == "High": risk_score += 3
        elif zap_risk == "Medium": risk_score += 2
        else: risk_score += 1
        
        # Riesgo de ML
        if ml_analysis.get("prediction", 0) != 0:
            risk_score += 2
        if ml_analysis.get("confidence", 0) > 0.8:
            risk_score += 1
        
        if risk_score >= 4: return "High"
        elif risk_score >= 3: return "Medium"
        return "Low"
    
    def _generate_recommendations(self, zap_results: Dict, ml_analysis: Dict) -> List[str]:
        recommendations = []
        
        if zap_results.get("alerts_found", 0) > 0:
            recommendations.append("🔒 Implementar medidas de seguridad web basadas en OWASP ZAP")
        
        if ml_analysis.get("prediction", 0) != 0:
            recommendations.append("🛡️ Revisar reglas de firewall y monitorear tráfico de red")
        
        if not recommendations:
            recommendations.append("✅ Estado de seguridad satisfactorio - Mantener monitoreo")
        
        return recommendations

# ==================== INSTANCIAS GLOBALES ====================
hybrid_system = HybridThreatDetectionSystem()

# ==================== MODELOS PYDANTIC ====================
class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "comprehensive"

class TrafficAnalysisRequest(BaseModel):
    analysis_type: str = "realtime"

# ==================== ENDPOINTS API ====================
@app.get("/")
async def root():
    return {
        "message": "🚀 Real Hybrid ML Threat Detection System",
        "version": "4.0",
        "status": "operational",
        "components": {
            "ml_model": hybrid_system.ml_model.is_loaded,
            "traffic_capture": hybrid_system.traffic_capture.is_capturing,
            "zap_scanner": hybrid_system.zap_scanner.is_available
        }
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "ml_model_loaded": hybrid_system.ml_model.is_loaded,
        "traffic_capture_active": hybrid_system.traffic_capture.is_capturing,
        "zap_available": hybrid_system.zap_scanner.is_available,
        "system_mode": "REAL_HYBRID"
    }

@app.post("/scan/website")
async def scan_website(request: ScanRequest):
    """Escaneo completo de website"""
    results = await hybrid_system.comprehensive_scan(request.target_url)
    return results

@app.get("/traffic/live")
async def get_live_traffic():
    """Obtener tráfico en tiempo real"""
    return {
        "live_traffic": hybrid_system.traffic_capture.get_recent_traffic(50),
        "stats": hybrid_system.traffic_capture.get_stats(),
        "suspicious_packets": hybrid_system.traffic_capture.suspicious_packets[-10:]
    }

@app.get("/analysis/realtime")
async def realtime_analysis():
    """Análisis en tiempo real del tráfico"""
    analysis = await hybrid_system.analyze_realtime_traffic()
    return {
        "timestamp": datetime.now().isoformat(),
        "analysis_results": analysis,
        "threats_detected": len([a for a in analysis if a["is_threat"]]),
        "total_analyzed": len(analysis)
    }

@app.get("/system/status")
async def system_status():
    """Estado completo del sistema"""
    traffic_stats = hybrid_system.traffic_capture.get_stats()
    
    return {
        "system": {
            "status": "operational",
            "mode": "hybrid_real_detection",
            "uptime": "active"
        },
        "components": {
            "ml_model": {
                "status": "loaded" if hybrid_system.ml_model.is_loaded else "simulation",
                "predictions": len(hybrid_system.detection_history)
            },
            "traffic_capture": {
                "status": "active" if traffic_stats["is_capturing"] else "inactive",
                "packets_captured": traffic_stats["total_packets"],
                "suspicious_packets": traffic_stats["suspicious_packets"]
            },
            "zap_scanner": {
                "status": "available" if hybrid_system.zap_scanner.is_available else "simulation"
            }
        }
    }

@app.get("/history/detections")
async def get_detection_history():
    """Obtener historial de detecciones"""
    return {
        "total_detections": len(hybrid_system.detection_history),
        "detections": hybrid_system.detection_history[-20:]  # Últimas 20 detecciones
    }

# ==================== INICIALIZACIÓN ====================
@app.on_event("startup")
async def startup_event():
    """Inicializar sistema al arrancar"""
    logger.info("🚀 Starting Hybrid Threat Detection System...")
    
    # Verificar componentes
    if hybrid_system.ml_model.is_loaded:
        logger.info("✅ ML Model: LOADED")
    else:
        logger.warning("⚠️ ML Model: SIMULATION MODE")
    
    if hybrid_system.traffic_capture.is_capturing:
        logger.info("✅ Traffic Capture: ACTIVE")
    else:
        logger.warning("⚠️ Traffic Capture: STARTING...")
    
    if hybrid_system.zap_scanner.is_available:
        logger.info("✅ OWASP ZAP: AVAILABLE")
    else:
        logger.warning("⚠️ OWASP ZAP: SIMULATION MODE")
    
    logger.info("🎯 Hybrid System Ready - Real Threat Detection Active")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)