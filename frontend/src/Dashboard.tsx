import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

interface MLAnalysis {
  prediction: number;
  confidence: number;
  attack_type: string;
  real_ml: boolean;
  success: boolean;
  mitre_id?: string;
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




const getAttackColor = (attackType: string) => {
  switch (attackType) {
    case 'DoS': return '#ef4444';
    case 'SQL Injection': return '#f59e0b';
    case 'XSS': return '#8b5cf6';
    case 'Path Traversal': return '#ec4899';
    case 'Suspicious Activity': return '#f97316';
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




const Dashboard: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('http://testphp.vulnweb.com');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<AnalysisResults | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [activeTab, setActiveTab] = useState<string>('All');

  const tabs = ['All', 'SQL Injection', 'XSS', 'Path Traversal', 'DoS', 'Normal'];

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
      {}
      <header className="header">
        <div className="header-content">
          <div className="header-icon">🛡️</div>
          <div className="header-text">
            <h1>Real ML Threat Detection</h1>
            <p>MITMProxy • Real Traffic Analysis • Machine Learning</p>
          </div>
        </div>
      </header>

      {}
      <div className="main-grid">
        {}
        <div className="left-column">
          {}
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
            </div>
          </div>
        </div>

        {}
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

              {}
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-icon">�</div>
                  <div className="stat-content">
                    <div className="stat-value">{results.stats.total_requests}</div>
                    <div className="stat-label">Total Requests</div>
                  </div>
                </div>
                <div className="stat-card threat-stat">
                  <div className="stat-icon">�🚨</div>
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

              {}
              <div className="traffic-section">
                <div className="section-header">
                  <h4>Recent Traffic</h4>
                  {results.stats.threats_detected > 0 && (
                    <div className="threat-alert">
                      🚨 {results.stats.threats_detected} threats detected
                    </div>
                  )}
                </div>
                
                <div className="tabs-container">
                  {tabs.map((tab) => (
                    <button
                      key={tab}
                      className={`tab-button ${activeTab === tab ? 'active' : ''}`}
                      onClick={() => setActiveTab(tab)}
                    >
                      {tab}
                    </button>
                  ))}
                </div>

                <div className="traffic-list">
                  {results.analysis_results
                    .filter((traffic) => activeTab === 'All' || traffic.ml_analysis.attack_type === activeTab)
                    .map((traffic, index) => {
                    const attackColor = getAttackColor(traffic.ml_analysis.attack_type);
                    const confidenceColor = getConfidenceColor(traffic.ml_analysis.confidence);
                    const confidenceLevel = getConfidenceLevel(traffic.ml_analysis.confidence);

                    return (
                      <div key={index} className={`traffic-item ${traffic.is_threat ? 'threat-item' : 'normal-item'}`}>
                        <div className="traffic-main">
                          <div className="traffic-left">
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
                          </div>

                          <div className="traffic-right">
                            <span
                              className="attack-type-compact"
                              style={{ color: attackColor, borderColor: attackColor }}
                            >
                              {traffic.ml_analysis.attack_type}
                            </span>
                            
                            {traffic.ml_analysis.mitre_id && (
                              <span className="mitre-compact">
                                {traffic.ml_analysis.mitre_id}
                              </span>
                            )}
                            
                            <span className="confidence-compact" style={{ color: confidenceColor }}>
                              {Math.round(traffic.ml_analysis.confidence * 100)}% ({confidenceLevel})
                            </span>
                          </div>
                        </div>

                        {traffic.ml_analysis.confidence < 0.6 && (
                          <div className="confidence-warning compact-warning">
                            <span className="warning-icon">⚠️</span>
                            Low confidence
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