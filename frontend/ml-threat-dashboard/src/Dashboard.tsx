import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE = 'http://localhost:8000';

interface MLAnalysis {
  prediction: number;
  confidence: number;
  attack_type: string;
  real_ml: boolean;
  success: boolean;
}

interface TrafficData {
  timestamp: string;
  url: string;
  method: string;
  src_ip: string;
  host?: string;
  path?: string;
  features: any;
  ml_analysis: MLAnalysis;
  is_threat: boolean;
  data_source: string;
}

interface AnalysisResults {
  analysis_results: TrafficData[];
  stats: {
    total_requests: number;
    threats_detected: number;
    unique_ips: number;
    unique_hosts: number;
    proxy_running: boolean;
    capture_duration: string;
    data_source: string;
  };
  proxy_status: string;
}

interface SystemStatus {
  system: {
    status: string;
    mode: string;
    proxy_active: boolean;
  };
  components: {
    ml_model: {
      status: string;
      real_model: boolean;
    };
    mitmproxy: {
      status: string;
      port: number;
    };
    traffic_capture: {
      status: string;
      data_source: string;
    };
  };
}

// =============================================================================
// COLOR SCHEME & STYLING
// =============================================================================
const getAttackColor = (attackType: string) => {
  switch(attackType) {
    case 'DoS': return '#ef4444';
    case 'Probe': return '#f59e0b';
    case 'R2L': return '#8b5cf6';
    case 'U2R': return '#ec4899';
    default: return '#10b981';
  }
};

const getConfidenceColor = (confidence: number) => {
  if (confidence >= 0.8) return '#10b981';
  if (confidence >= 0.6) return '#f59e0b';
  return '#ef4444';
};

const getConfidenceLevel = (confidence: number) => {
  if (confidence >= 0.8) return 'High';
  if (confidence >= 0.6) return 'Medium';
  return 'Low';
};

// =============================================================================
// MAIN DASHBOARD COMPONENT
// =============================================================================
const Dashboard: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('http://testphp.vulnweb.com');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<AnalysisResults | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);

  const startScan = async () => {
    setIsScanning(true);
    try {
      await axios.post(`${API_BASE}/scan/start`, { target_url: targetUrl });
      alert('🚀 MITMProxy started! Configure browser proxy: 127.0.0.1:8080');
    } catch (error) {
      console.error('Scan start error:', error);
      alert('Error starting proxy');
    }
    setIsScanning(false);
  };

  const fetchResults = async () => {
    try {
      const response = await axios.get(`${API_BASE}/analysis/results`);
      setResults(response.data);
    } catch (error) {
      console.error('Fetch error:', error);
    }
  };

  const fetchSystemStatus = async () => {
    try {
      const response = await axios.get(`${API_BASE}/system/status`);
      setSystemStatus(response.data);
    } catch (error) {
      console.error('Status fetch error:', error);
    }
  };

  useEffect(() => {
    fetchSystemStatus();
    const interval = setInterval(fetchResults, 3000);
    return () => clearInterval(interval);
  }, []);

  const getDisplayUrl = (traffic: TrafficData): string => {
    if (traffic.host && traffic.path) {
      return `${traffic.host}${traffic.path}`;
    }
    return traffic.url || 'Unknown URL';
  };

  return (
    <div className="dashboard">
      {/* HEADER WITH GRADIENT */}
      <header className="header">
        <div className="header-content">
          <div className="header-icon">🛡️</div>
          <div className="header-text">
            <h1>Real ML Threat Detection</h1>
            <p>MITMProxy • Real Traffic Analysis • Machine Learning</p>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT GRID */}
      <div className="main-grid">
        {/* LEFT COLUMN - CONTROLS & STATUS */}
        <div className="left-column">
          {/* SCANNER CONTROL CARD */}
          <div className="scanner-card glass-card">
            <div className="card-header">
              <div className="card-icon">🔍</div>
              <h3>Start Traffic Analysis</h3>
            </div>
            <div className="controls">
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="Enter target website URL..."
                className="url-input"
              />
              <button 
                onClick={startScan} 
                disabled={isScanning} 
                className={`scan-btn ${isScanning ? 'scanning' : ''}`}
              >
                <span className="btn-icon">
                  {isScanning ? '🔄' : '🚀'}
                </span>
                <span className="btn-text">
                  {isScanning ? 'Starting Proxy...' : 'Start MITMProxy & Scan'}
                </span>
              </button>
            </div>
            <div className="proxy-info">
              <div className="info-row">
                <span className="info-label">Proxy Config:</span>
                <span className="info-value">127.0.0.1:8080</span>
              </div>
              <div className="info-row">
                <span className="info-label">Data Source:</span>
                <span className="info-value highlight">REAL TRAFFIC</span>
              </div>
              <div className="instruction">
                💡 Set this proxy in your browser and browse naturally
              </div>
            </div>
          </div>

          {/* SYSTEM STATUS CARD */}
          {systemStatus && (
            <div className="status-card glass-card">
              <div className="card-header">
                <div className="card-icon">🖥️</div>
                <h3>System Status</h3>
              </div>
              <div className="status-grid">
                <div className={`status-item ${systemStatus.components.ml_model.real_model ? 'status-success' : 'status-warning'}`}>
                  <div className="status-icon">🤖</div>
                  <div className="status-content">
                    <div className="status-label">ML Model</div>
                    <div className="status-value">
                      {systemStatus.components.ml_model.real_model ? 'REAL MODEL' : 'SIMULATION'}
                    </div>
                  </div>
                </div>
                <div className={`status-item ${systemStatus.components.mitmproxy.status === 'running' ? 'status-success' : 'status-warning'}`}>
                  <div className="status-icon">📡</div>
                  <div className="status-content">
                    <div className="status-label">MITMProxy</div>
                    <div className="status-value">{systemStatus.components.mitmproxy.status.toUpperCase()}</div>
                  </div>
                </div>
                <div className="status-item status-success">
                  <div className="status-icon">🌐</div>
                  <div className="status-content">
                    <div className="status-label">Data Source</div>
                    <div className="status-value">REAL TRAFFIC</div>
                  </div>
                </div>
                <div className="status-item status-success">
                  <div className="status-icon">⚡</div>
                  <div className="status-content">
                    <div className="status-label">Mode</div>
                    <div className="status-value">LIVE ANALYSIS</div>
                  </div>
                </div>
              </div>
              {systemStatus.components.mitmproxy.status === 'running' && (
                <div className="proxy-active">
                  <div className="active-indicator"></div>
                  <span>🟢 Actively capturing REAL traffic</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* RIGHT COLUMN - RESULTS */}
        <div className="right-column">
          {results && (
            <div className="results-card glass-card">
              <div className="card-header">
                <div className="card-icon">📊</div>
                <h3>Real-time Traffic Analysis</h3>
                <div className="requests-count">
                  {results.stats.total_requests} requests
                </div>
              </div>
              
              {/* STATISTICS GRID */}
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-icon">📨</div>
                  <div className="stat-content">
                    <div className="stat-value">{results.stats.total_requests}</div>
                    <div className="stat-label">Total Requests</div>
                  </div>
                </div>
                <div className="stat-card threat-stat">
                  <div className="stat-icon">🚨</div>
                  <div className="stat-content">
                    <div className="stat-value">{results.stats.threats_detected}</div>
                    <div className="stat-label">Threats Detected</div>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">🌍</div>
                  <div className="stat-content">
                    <div className="stat-value">{results.stats.unique_hosts}</div>
                    <div className="stat-label">Unique Hosts</div>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">🖧</div>
                  <div className="stat-content">
                    <div className="stat-value">{results.stats.unique_ips}</div>
                    <div className="stat-label">Source IPs</div>
                  </div>
                </div>
              </div>

              {/* TRAFFIC LIST WITH SCROLL */}
              <div className="traffic-section">
                <div className="section-header">
                  <h4>Recent Traffic</h4>
                  {results.stats.threats_detected > 0 && (
                    <div className="threat-alert">
                      🚨 {results.stats.threats_detected} threats detected
                    </div>
                  )}
                </div>
                <div className="traffic-list">
                  {results.analysis_results.map((traffic, index) => {
                    const attackColor = getAttackColor(traffic.ml_analysis.attack_type);
                    const confidenceColor = getConfidenceColor(traffic.ml_analysis.confidence);
                    const confidenceLevel = getConfidenceLevel(traffic.ml_analysis.confidence);
                    
                    return (
                      <div key={index} className={`traffic-item ${traffic.is_threat ? 'threat-item' : 'normal-item'}`}>
                        <div className="traffic-main">
                          <div className="method-badge" style={{ backgroundColor: attackColor }}>
                            {traffic.method}
                          </div>
                          <div className="traffic-content">
                            <div className="url" title={traffic.url}>
                              {getDisplayUrl(traffic)}
                            </div>
                            <div className="traffic-meta">
                              <span className="source">{traffic.src_ip}</span>
                              <span className="timestamp">
                                {new Date(traffic.timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                          </div>
                          <div className="traffic-status">
                            <div 
                              className={`threat-badge ${traffic.is_threat ? 'threat' : 'normal'}`}
                              style={{ 
                                backgroundColor: traffic.is_threat ? '#ef4444' : '#10b981'
                              }}
                            >
                              {traffic.is_threat ? 'THREAT' : 'NORMAL'}
                            </div>
                          </div>
                        </div>
                        
                        <div className="traffic-details">
                          <div className="detail-group">
                            <div className="detail-item">
                              <span className="detail-label">Attack Type:</span>
                              <span 
                                className="attack-type"
                                style={{ color: attackColor }}
                              >
                                {traffic.ml_analysis.attack_type}
                              </span>
                            </div>
                            <div className="detail-item">
                              <span className="detail-label">Confidence:</span>
                              <div className="confidence-display">
                                <div 
                                  className="confidence-bar"
                                  style={{ 
                                    width: `${traffic.ml_analysis.confidence * 100}%`,
                                    backgroundColor: confidenceColor
                                  }}
                                ></div>
                                <span 
                                  className="confidence-value"
                                  style={{ color: confidenceColor }}
                                >
                                  {Math.round(traffic.ml_analysis.confidence * 100)}% ({confidenceLevel})
                                </span>
                              </div>
                            </div>
                          </div>
                          
                          {traffic.ml_analysis.real_ml && (
                            <div className="ml-badge">
                              🤖 Real ML Analysis
                            </div>
                          )}
                        </div>

                        {traffic.ml_analysis.confidence < 0.6 && (
                          <div className="confidence-warning">
                            <span className="warning-icon">⚠️</span>
                            Low confidence prediction - Consider model retraining
                          </div>
                        )}
                      </div>
                    );
                  })}
                  
                  {results.analysis_results.length === 0 && (
                    <div className="no-traffic">
                      <div className="no-traffic-icon">📡</div>
                      <div className="no-traffic-text">
                        <h4>No Traffic Data</h4>
                        <p>Start the proxy and browse websites to see traffic analysis</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {!results && (
            <div className="welcome-card glass-card">
              <div className="welcome-content">
                <div className="welcome-icon">🎯</div>
                <h3>Welcome to ML Threat Detection</h3>
                <p>Start the MITMProxy to begin analyzing real web traffic in real-time</p>
                <div className="features-grid">
                  <div className="feature">
                    <span className="feature-icon">🔍</span>
                    <span>Real Traffic Capture</span>
                  </div>
                  <div className="feature">
                    <span className="feature-icon">🤖</span>
                    <span>ML Analysis</span>
                  </div>
                  <div className="feature">
                    <span className="feature-icon">🚨</span>
                    <span>Threat Detection</span>
                  </div>
                  <div className="feature">
                    <span className="feature-icon">📊</span>
                    <span>Live Statistics</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;