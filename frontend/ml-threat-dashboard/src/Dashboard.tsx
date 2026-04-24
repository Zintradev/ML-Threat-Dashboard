// frontend/src/App.tsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

// Importar tipos
import {
  SystemStatus,
  TrafficPacket,
  TrafficStats,
  RealTimeAnalysis,
  ScanResults,
  DetectionHistoryItem,
  MLAnalysis,
  ZAPAlert,
  ZAPScan
} from './types';

const API_BASE = 'http://127.0.0.1:8000';

// Valores por defecto con tipos explícitos
const DEFAULT_SYSTEM_STATUS: SystemStatus = {
  system: { 
    status: 'checking', 
    mode: 'unknown', 
    uptime: 'unknown' 
  },
  components: {
    ml_model: { 
      status: 'checking', 
      predictions: 0 
    },
    traffic_capture: { 
      status: 'checking', 
      packets_captured: 0, 
      suspicious_packets: 0 
    },
    zap_scanner: { 
      status: 'checking' 
    }
  }
};

const DEFAULT_TRAFFIC_STATS: TrafficStats = {
  total_packets: 0,
  suspicious_packets: 0,
  is_capturing: false,
  buffer_size: 0
};

const DEFAULT_ML_ANALYSIS: MLAnalysis = {
  prediction: 0,
  probability: 0,
  confidence: 0,
  attack_type: 'Unknown',
  real_ml: false,
  success: false
};

const DEFAULT_TRAFFIC_PACKET: TrafficPacket = {
  timestamp: new Date().toISOString(),
  src_ip: 'Unknown',
  dst_ip: 'Unknown',
  protocol: 'Unknown',
  size: 0,
  src_port: 0,
  dst_port: 0,
  flags: '',
  ttl: 0,
  suspicious: false
};

const DEFAULT_ZAP_SCAN: ZAPScan = {
  real_scan: false,
  target: 'Unknown',
  alerts_found: 0,
  alerts: [],
  risk_summary: 'Unknown'
};

const DEFAULT_SCAN_RESULTS: ScanResults = {
  scan_type: 'comprehensive',
  target_url: 'Unknown',
  timestamp: new Date().toISOString(),
  zap_scan: DEFAULT_ZAP_SCAN,
  ml_analysis: DEFAULT_ML_ANALYSIS,
  overall_risk: 'Unknown',
  recommendations: []
};

const DEFAULT_REAL_TIME_ANALYSIS: RealTimeAnalysis = {
  packet_info: DEFAULT_TRAFFIC_PACKET,
  ml_analysis: DEFAULT_ML_ANALYSIS,
  timestamp: new Date().toISOString(),
  is_threat: false
};

// Funciones helper con tipos explícitos
const createSafeSystemStatus = (data: any): SystemStatus => {
  if (!data || typeof data !== 'object') {
    return DEFAULT_SYSTEM_STATUS;
  }

  return {
    system: {
      status: data.system?.status || 'checking',
      mode: data.system?.mode || 'unknown',
      uptime: data.system?.uptime || 'unknown'
    },
    components: {
      ml_model: {
        status: data.components?.ml_model?.status || 'checking',
        predictions: data.components?.ml_model?.predictions || 0
      },
      traffic_capture: {
        status: data.components?.traffic_capture?.status || 'checking',
        packets_captured: data.components?.traffic_capture?.packets_captured || 0,
        suspicious_packets: data.components?.traffic_capture?.suspicious_packets || 0
      },
      zap_scanner: {
        status: data.components?.zap_scanner?.status || 'checking'
      }
    }
  };
};

const createSafeTrafficStats = (data: any): TrafficStats => {
  if (!data || typeof data !== 'object') {
    return DEFAULT_TRAFFIC_STATS;
  }

  return {
    total_packets: data.total_packets || 0,
    suspicious_packets: data.suspicious_packets || 0,
    is_capturing: data.is_capturing || false,
    buffer_size: data.buffer_size || 0
  };
};

const createSafeTrafficPacket = (data: any): TrafficPacket => {
  if (!data || typeof data !== 'object') {
    return DEFAULT_TRAFFIC_PACKET;
  }

  return {
    timestamp: data.timestamp || new Date().toISOString(),
    src_ip: data.src_ip || 'Unknown',
    dst_ip: data.dst_ip || 'Unknown',
    protocol: data.protocol || 'Unknown',
    size: data.size || 0,
    src_port: data.src_port || 0,
    dst_port: data.dst_port || 0,
    flags: data.flags || '',
    ttl: data.ttl || 0,
    suspicious: data.suspicious || false
  };
};

const createSafeMLAnalysis = (data: any): MLAnalysis => {
  if (!data || typeof data !== 'object') {
    return DEFAULT_ML_ANALYSIS;
  }

  return {
    prediction: data.prediction || 0,
    probability: data.probability || 0,
    confidence: data.confidence || 0,
    attack_type: data.attack_type || 'Unknown',
    real_ml: data.real_ml || false,
    success: data.success || false
  };
};

const createSafeZAPAlert = (data: any): ZAPAlert => {
  if (!data || typeof data !== 'object') {
    return { risk: 'Low', alert: 'Unknown Alert' };
  }

  return {
    alert: data.alert || data.name || 'Unknown Alert',
    risk: data.risk || 'Low',
    url: data.url || '',
    description: data.description || data.desc || 'No description available'
  };
};

const createSafeScanResults = (data: any): ScanResults => {
  if (!data || typeof data !== 'object') {
    return DEFAULT_SCAN_RESULTS;
  }

  const alerts: ZAPAlert[] = Array.isArray(data.zap_scan?.alerts) 
    ? data.zap_scan.alerts.map(createSafeZAPAlert)
    : [];

  return {
    scan_type: data.scan_type || 'comprehensive',
    target_url: data.target_url || 'Unknown',
    timestamp: data.timestamp || new Date().toISOString(),
    zap_scan: {
      real_scan: data.zap_scan?.real_scan || false,
      target: data.zap_scan?.target || 'Unknown',
      alerts_found: data.zap_scan?.alerts_found || 0,
      alerts: alerts,
      risk_summary: data.zap_scan?.risk_summary || 'Unknown'
    },
    ml_analysis: createSafeMLAnalysis(data.ml_analysis),
    overall_risk: data.overall_risk || 'Unknown',
    recommendations: Array.isArray(data.recommendations) ? data.recommendations : []
  };
};

const createSafeRealTimeAnalysis = (data: any): RealTimeAnalysis => {
  if (!data || typeof data !== 'object') {
    return DEFAULT_REAL_TIME_ANALYSIS;
  }

  return {
    is_threat: Boolean(data.is_threat),
    timestamp: data.timestamp || new Date().toISOString(),
    packet_info: createSafeTrafficPacket(data.packet_info),
    ml_analysis: createSafeMLAnalysis(data.ml_analysis)
  };
};

// Componente principal con TypeScript
const Dashboard: React.FC = () => {
  // Estados con tipos explícitos
  const [systemStatus, setSystemStatus] = useState<SystemStatus>(DEFAULT_SYSTEM_STATUS);
  const [liveTraffic, setLiveTraffic] = useState<TrafficPacket[]>([]);
  const [trafficStats, setTrafficStats] = useState<TrafficStats>(DEFAULT_TRAFFIC_STATS);
  const [realTimeAnalysis, setRealTimeAnalysis] = useState<RealTimeAnalysis[]>([]);
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [detectionHistory, setDetectionHistory] = useState<DetectionHistoryItem[]>([]);
  const [targetUrl, setTargetUrl] = useState<string>('http://testphp.vulnweb.com');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>('overview');

  // Estado del sistema en tiempo real
  useEffect(() => {
    const checkSystemStatus = async () => {
      try {
        const response = await axios.get(`${API_BASE}/system/status`);
        setSystemStatus(createSafeSystemStatus(response.data));
      } catch (error) {
        console.error('Error checking system status:', error);
      }
    };

    checkSystemStatus();
    const interval = setInterval(checkSystemStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  // Tráfico en tiempo real
  useEffect(() => {
    const fetchLiveTraffic = async () => {
      try {
        const response = await axios.get(`${API_BASE}/traffic/live`);
        if (response.data) {
          const trafficData: TrafficPacket[] = Array.isArray(response.data.live_traffic) 
            ? response.data.live_traffic.map(createSafeTrafficPacket)
            : [];
          setLiveTraffic(trafficData);
          setTrafficStats(createSafeTrafficStats(response.data.stats));
        }
      } catch (error) {
        console.error('Error fetching live traffic:', error);
      }
    };

    fetchLiveTraffic();
    const interval = setInterval(fetchLiveTraffic, 3000);
    return () => clearInterval(interval);
  }, []);

  // Análisis en tiempo real
  useEffect(() => {
    const fetchRealTimeAnalysis = async () => {
      try {
        const response = await axios.get(`${API_BASE}/analysis/realtime`);
        if (response.data) {
          const analysisData: RealTimeAnalysis[] = Array.isArray(response.data.analysis_results)
            ? response.data.analysis_results.map(createSafeRealTimeAnalysis)
            : [];
          setRealTimeAnalysis(analysisData);
          
          if (response.data.threats_detected > 0) {
            const historyResponse = await axios.get(`${API_BASE}/history/detections`);
            const historyData: DetectionHistoryItem[] = Array.isArray(historyResponse.data.detections)
              ? historyResponse.data.detections.map(createSafeRealTimeAnalysis)
              : [];
            setDetectionHistory(historyData);
          }
        }
      } catch (error) {
        console.error('Error fetching real-time analysis:', error);
      }
    };

    fetchRealTimeAnalysis();
    const interval = setInterval(fetchRealTimeAnalysis, 5000);
    return () => clearInterval(interval);
  }, []);

  // Escaneo completo de website
  const performWebsiteScan = async (): Promise<void> => {
    setIsScanning(true);
    try {
      const response = await axios.post(`${API_BASE}/scan/website`, {
        target_url: targetUrl,
        scan_type: "comprehensive"
      });
      setScanResults(createSafeScanResults(response.data));
      setActiveTab('scanResults');
    } catch (error) {
      console.error('Scan error:', error);
      alert('Error performing scan');
    }
    setIsScanning(false);
  };

  // Componente de Estado del Sistema
  const SystemStatusCard: React.FC = () => (
    <div className="status-card">
      <h3>🖥️ System Status</h3>
      <div className="status-grid">
        <div className={`status-item ${systemStatus.components.ml_model.status === 'loaded' ? 'active' : 'warning'}`}>
          <span>🤖 ML Model</span>
          <strong>{systemStatus.components.ml_model.status}</strong>
        </div>
        <div className={`status-item ${systemStatus.components.traffic_capture.status === 'active' ? 'active' : 'warning'}`}>
          <span>📡 Traffic Capture</span>
          <strong>{systemStatus.components.traffic_capture.status}</strong>
        </div>
        <div className={`status-item ${systemStatus.components.zap_scanner.status === 'available' ? 'active' : 'warning'}`}>
          <span>🛡️ OWASP ZAP</span>
          <strong>{systemStatus.components.zap_scanner.status}</strong>
        </div>
        <div className="status-item active">
          <span>⚡ Mode</span>
          <strong>HYBRID REAL-TIME</strong>
        </div>
      </div>
    </div>
  );

  // Componente de Estadísticas de Tráfico
  const TrafficStatsCard: React.FC = () => (
    <div className="stats-card">
      <h3>📊 Live Traffic Statistics</h3>
      <div className="stats-grid">
        <div className="stat">
          <span className="stat-value">{trafficStats.total_packets}</span>
          <span className="stat-label">Total Packets</span>
        </div>
        <div className="stat">
          <span className="stat-value">{trafficStats.suspicious_packets}</span>
          <span className="stat-label">Suspicious</span>
        </div>
        <div className="stat">
          <span className="stat-value">{realTimeAnalysis.filter(a => a.is_threat).length}</span>
          <span className="stat-label">Threats Detected</span>
        </div>
        <div className="stat">
          <span className="stat-value">{detectionHistory.length}</span>
          <span className="stat-label">Total Detections</span>
        </div>
      </div>
    </div>
  );

  // Componente de Tráfico en Tiempo Real
  const LiveTrafficMonitor: React.FC = () => (
    <div className="traffic-card">
      <h3>🌐 Live Network Traffic</h3>
      <div className="traffic-list">
        {liveTraffic.slice(-10).map((packet: TrafficPacket, index: number) => (
          <div key={index} className={`traffic-item ${packet.suspicious ? 'suspicious' : ''}`}>
            <div className="traffic-header">
              <span className="protocol">{packet.protocol}</span>
              <span className="time">{new Date(packet.timestamp).toLocaleTimeString()}</span>
            </div>
            <div className="traffic-details">
              <span className="ip-address">{packet.src_ip}:{packet.src_port}</span>
              <span className="arrow">→</span>
              <span className="ip-address">{packet.dst_ip}:{packet.dst_port}</span>
              <span className="size">{packet.size} bytes</span>
            </div>
            {packet.suspicious && <span className="suspicious-badge">⚠️ Suspicious</span>}
          </div>
        ))}
        {liveTraffic.length === 0 && (
          <div className="no-data">No traffic data available</div>
        )}
      </div>
    </div>
  );

  // Componente de Análisis ML en Tiempo Real
  const MLRealTimeAnalysis: React.FC = () => (
    <div className="analysis-card">
      <h3>🔍 Real-Time ML Analysis</h3>
      <div className="analysis-list">
        {realTimeAnalysis.slice(-8).map((analysis: RealTimeAnalysis, index: number) => (
          <div key={index} className={`analysis-item ${analysis.is_threat ? 'threat' : 'normal'}`}>
            <div className="analysis-header">
              <span className="result">
                {analysis.is_threat ? '🚨 THREAT' : '✅ NORMAL'}
              </span>
              <span className="confidence">
                {Math.round(analysis.ml_analysis.confidence * 100)}% conf
              </span>
            </div>
            <div className="analysis-details">
              <span className="type">{analysis.ml_analysis.attack_type}</span>
              <span className="model">
                {analysis.ml_analysis.real_ml ? '🤖 Real ML' : '🧪 Simulation'}
              </span>
            </div>
            <div className="packet-info">
              {analysis.packet_info.src_ip} → {analysis.packet_info.dst_ip}
            </div>
          </div>
        ))}
        {realTimeAnalysis.length === 0 && (
          <div className="no-data">No analysis data available</div>
        )}
      </div>
    </div>
  );

  // Componente de Escaneo OWASP
  const OWASPScanner: React.FC = () => (
    <div className="scanner-card">
      <h3>🛡️ OWASP ZAP + ML Scanner</h3>
      <div className="scanner-controls">
        <input
          type="text"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          placeholder="Enter target URL (e.g., http://example.com)"
          className="url-input"
        />
        <button 
          onClick={performWebsiteScan}
          disabled={isScanning}
          className={`scan-button ${isScanning ? 'scanning' : ''}`}
        >
          {isScanning ? '🔍 Scanning...' : '🚀 Start Comprehensive Scan'}
        </button>
      </div>
      <div className="scanner-info">
        <p><strong>Real Pipeline:</strong> OWASP ZAP → Traffic Analysis → ML Classification</p>
        <p><strong>Current Target:</strong> {targetUrl}</p>
        {systemStatus.components.zap_scanner.status === 'simulation' && (
          <p className="warning-text">⚠️ OWASP ZAP Simulation Mode - Install ZAP for real scanning</p>
        )}
      </div>
    </div>
  );

  // Componente de Resultados de Escaneo
  const ScanResultsView: React.FC = () => {
    const safeScanResults: ScanResults = scanResults || DEFAULT_SCAN_RESULTS;

    return (
      <div className="scan-results-card">
        <h3>📋 Scan Results - {safeScanResults.target_url}</h3>
        
        <div className="overall-risk">
          <h4>Overall Risk: 
            <span className={`risk-${safeScanResults.overall_risk.toLowerCase()}`}>
              {safeScanResults.overall_risk}
            </span>
          </h4>
        </div>

        <div className="results-grid">
          <div className="result-section">
            <h5>🛡️ OWASP ZAP Findings</h5>
            <div className="zap-alerts">
              {safeScanResults.zap_scan.alerts.map((alert: ZAPAlert, index: number) => (
                <div key={index} className={`alert-item ${alert.risk.toLowerCase()}`}>
                  <div className="alert-header">
                    <span className="alert-name">{alert.alert}</span>
                    <span className={`risk-badge ${alert.risk.toLowerCase()}`}>
                      {alert.risk}
                    </span>
                  </div>
                  <div className="alert-details">
                    {alert.description}
                  </div>
                  {alert.url && <div className="alert-url">URL: {alert.url}</div>}
                </div>
              ))}
              {safeScanResults.zap_scan.alerts.length === 0 && (
                <div className="no-data">No security issues found</div>
              )}
            </div>
          </div>

          <div className="result-section">
            <h5>🤖 ML Analysis</h5>
            <div className={`ml-result ${safeScanResults.ml_analysis.prediction !== 0 ? 'threat' : 'normal'}`}>
              <div className="ml-header">
                <span className="result">
                  {safeScanResults.ml_analysis.prediction !== 0 ? '🚨 ATTACK DETECTED' : '✅ NORMAL TRAFFIC'}
                </span>
                <span className="confidence">
                  {Math.round(safeScanResults.ml_analysis.confidence * 100)}% confidence
                </span>
              </div>
              <div className="ml-details">
                <p><strong>Type:</strong> {safeScanResults.ml_analysis.attack_type}</p>
                <p><strong>Model:</strong> {safeScanResults.ml_analysis.real_ml ? 'Real ML Model' : 'Simulation'}</p>
                <p><strong>Probability:</strong> {(safeScanResults.ml_analysis.probability * 100).toFixed(1)}%</p>
              </div>
            </div>
          </div>
        </div>

        <div className="recommendations">
          <h5>💡 Security Recommendations</h5>
          <ul>
            {safeScanResults.recommendations.map((rec: string, index: number) => (
              <li key={index}>{rec}</li>
            ))}
          </ul>
        </div>
      </div>
    );
  };

  // Componente de Historial de Detecciones
  const DetectionHistoryView: React.FC = () => (
    <div className="history-card">
      <h3>📜 Detection History</h3>
      <div className="history-list">
        {detectionHistory.slice(-15).map((detection: DetectionHistoryItem, index: number) => (
          <div key={index} className="history-item">
            <div className="history-header">
              <span className="threat-level">
                {detection.is_threat ? '🚨 THREAT' : '⚠️ SUSPICIOUS'}
              </span>
              <span className="timestamp">
                {new Date(detection.timestamp).toLocaleString()}
              </span>
            </div>
            <div className="history-details">
              <p><strong>ML Analysis:</strong> {detection.ml_analysis.attack_type} 
                ({Math.round(detection.ml_analysis.confidence * 100)}% confidence)
              </p>
              <p><strong>Traffic:</strong> {detection.packet_info.src_ip} → {detection.packet_info.dst_ip}</p>
              <p><strong>Protocol:</strong> {detection.packet_info.protocol}</p>
            </div>
          </div>
        ))}
        {detectionHistory.length === 0 && (
          <div className="no-data">No detection history available</div>
        )}
      </div>
    </div>
  );

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div className="header-content">
          <h1>🛡️ HYBRID ML THREAT DETECTOR</h1>
          <p>Real-Time Network Analysis • OWASP ZAP Integration • Machine Learning</p>
        </div>
        <div className="header-status">
          <span className={`status-badge ${systemStatus.system.status === 'operational' ? 'online' : 'offline'}`}>
            {systemStatus.system.status.toUpperCase()}
          </span>
        </div>
      </header>

      <nav className="tabs">
        <button 
          className={activeTab === 'overview' ? 'active' : ''}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button 
          className={activeTab === 'scanResults' ? 'active' : ''}
          onClick={() => setActiveTab('scanResults')}
        >
          🔍 Scan Results
        </button>
        <button 
          className={activeTab === 'history' ? 'active' : ''}
          onClick={() => setActiveTab('history')}
        >
          📜 Detection History
        </button>
      </nav>

      <main className="dashboard-content">
        {activeTab === 'overview' && (
          <>
            <div className="top-row">
              <SystemStatusCard />
              <OWASPScanner />
            </div>
            <TrafficStatsCard />
            <div className="monitoring-row">
              <LiveTrafficMonitor />
              <MLRealTimeAnalysis />
            </div>
          </>
        )}

        {activeTab === 'scanResults' && <ScanResultsView />}
        {activeTab === 'history' && <DetectionHistoryView />}
      </main>

      <footer className="dashboard-footer">
        <p>Hybrid ML Threat Detector v4.0 • Real-Time Network Security • OWASP ZAP Integration</p>
        <p>Powered by Machine Learning & Real Traffic Analysis</p>
      </footer>
    </div>
  );
};

export default Dashboard;