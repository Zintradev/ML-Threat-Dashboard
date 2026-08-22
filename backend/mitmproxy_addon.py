from mitmproxy import http
import requests
import time
import logging

# Ensure logging is properly configured for mitmproxy
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class TrafficCaptureAddon:
    def __init__(self):
        self.api_url = "http://127.0.0.1:8000/capture/request"
             
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
                         
            try:
                requests.post(self.api_url, json=request_data, timeout=1.0)
            except requests.Timeout as t_err:
                logger.warning(f"Timeout sending request data to dashboard API: {t_err}")
            except requests.ConnectionError as c_err:
                logger.error(f"Connection error sending request data to dashboard API: {c_err}")
            except requests.RequestException as req_err:
                logger.error(f"Request exception sending request data to dashboard API: {req_err}")
                         
        except Exception as e:
            logger.error(f"Unexpected error capturing request: {e}")
         
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
                requests.post(self.api_url, json=request_data, timeout=1.0)
            except requests.Timeout as t_err:
                logger.warning(f"Timeout sending response data to dashboard API: {t_err}")
            except requests.ConnectionError as c_err:
                logger.error(f"Connection error sending response data to dashboard API: {c_err}")
            except requests.RequestException as req_err:
                logger.error(f"Request exception sending response data to dashboard API: {req_err}")
                         
        except Exception as e:
            logger.error(f"Unexpected error capturing response: {e}")

addons = [TrafficCaptureAddon()]