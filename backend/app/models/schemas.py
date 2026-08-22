from pydantic import BaseModel
from typing import Optional

class ScanRequest(BaseModel):
    target_url: str

class TrafficRequest(BaseModel):
    timestamp: float
    url: str
    method: str
    src_ip: str
    host: Optional[str] = None
    path: Optional[str] = None
    content_length: Optional[int] = 0
    query_params: Optional[dict] = {}
    status_code: Optional[int] = 200
