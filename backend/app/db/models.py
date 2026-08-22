from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime
from app.db.database import Base

class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    method = Column(String, index=True)
    url = Column(String)
    source_ip = Column(String, index=True)
    attack_type = Column(String)
    confidence = Column(Float)
    mitre_id = Column(String, nullable=True)
