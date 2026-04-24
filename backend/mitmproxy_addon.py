from mitmproxy import http, ctx
import requests
import json
import time

class TrafficCaptureAddon:
    def __init__(self):
        self.api_url = "http://localhost:8000/capture/request"
        
    def request(self, flow: http.HTTPFlow) -> None:
        """Capture HTTP requests"""
        try:
            request_data = {
                "timestamp": time.time(),
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "src_ip": flow.client_conn.address[0] if flow.client_conn else "unknown",
                "host": flow.request.host,
                "path": flow.request.path,
                "content_length": len(flow.request.content) if flow.request.content else 0,
                "query_params": dict(flow.request.query),
                "headers": dict(flow.request.headers)
            }
            
            # Send to analysis API
            try:
                requests.post(self.api_url, json=request_data, timeout=1)
            except:
                pass
                
        except Exception as e:
            ctx.log.error(f"Error capturing request: {e}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Capture HTTP responses"""
        try:
            request_data = {
                "timestamp": time.time(),
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "src_ip": flow.client_conn.address[0] if flow.client_conn else "unknown",
                "host": flow.request.host,
                "path": flow.request.path,
                "content_length": len(flow.request.content) if flow.request.content else 0,
                "status_code": flow.response.status_code,
                "query_params": dict(flow.request.query)
            }
            
            try:
                requests.post(self.api_url, json=request_data, timeout=1)
            except:
                pass
                
        except Exception as e:
            ctx.log.error(f"Error capturing response: {e}")

addons = [TrafficCaptureAddon()]
