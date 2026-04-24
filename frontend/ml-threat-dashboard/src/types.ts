
export interface SystemStatus {
  system: {
    status: string;
    mode: string;
    uptime: string;
  };
  components: {
    ml_model: {
      status: string;
      predictions: number;
    };
    traffic_capture: {
      status: string;
      packets_captured: number;
      suspicious_packets: number;
    };
    zap_scanner: {
      status: string;
    };
  };
}

export interface TrafficPacket {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  size: number;
  src_port: number;
  dst_port: number;
  flags: string;
  ttl: number;
  suspicious?: boolean;
}

export interface MLAnalysis {
  prediction: number;
  probability: number;
  confidence: number;
  attack_type: string;
  real_ml: boolean;
  success: boolean;
}

export interface RealTimeAnalysis {
  packet_info: TrafficPacket;
  ml_analysis: MLAnalysis;
  timestamp: string;
  is_threat: boolean;
}

export interface ZAPAlert {
  alert?: string;
  name?: string;
  risk: string;
  url?: string;
  description?: string;
  desc?: string;
}

export interface ZAPScan {
  real_scan: boolean;
  target: string;
  alerts_found: number;
  alerts: ZAPAlert[];
  risk_summary: string;
}

export interface ScanResults {
  scan_type: string;
  target_url: string;
  timestamp: string;
  zap_scan: ZAPScan;
  ml_analysis: MLAnalysis;
  overall_risk: string;
  recommendations: string[];
}

export interface TrafficStats {
  total_packets: number;
  suspicious_packets: number;
  is_capturing: boolean;
  buffer_size: number;
}

export interface DetectionHistoryItem {
  packet_info: TrafficPacket;
  ml_analysis: MLAnalysis;
  timestamp: string;
  is_threat: boolean;
}