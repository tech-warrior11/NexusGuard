"""
SQLAlchemy Model for Ingested and Normalized Security Logs
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.core.database import Base


class SecurityLog(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source = Column(String(50), index=True, nullable=False)        # linux, windows, network, firewall, web, auth, endpoint
    event_type = Column(String(50), index=True, nullable=False)    # authentication, network_scan, privilege_escalation, powershell_exec, malware_detected, c2_traffic, logon_4625, logon_4624
    username = Column(String(100), index=True, nullable=True)
    source_ip = Column(String(45), index=True, nullable=True)      # IPv4 / IPv6
    destination_ip = Column(String(45), index=True, nullable=True) # IPv4 / IPv6
    port = Column(Integer, index=True, nullable=True)              # 22, 80, 443, 3389, 445, etc.
    protocol = Column(String(20), index=True, nullable=True)       # TCP, UDP, ICMP, HTTP, HTTPS, SSH, RDP
    action = Column(String(50), nullable=True)                     # login, connect, sudo, file_read, execute, scan
    status = Column(String(20), index=True, nullable=False)        # success, failed, denied, error, blocked, detected
    message = Column(Text, nullable=True)
    raw_payload = Column(Text, nullable=True)                      # Raw packet / Windows XML / auth.log string

    def __repr__(self):
        return f"<SecurityLog(id={self.id}, source='{self.source}', type='{self.event_type}', ip='{self.source_ip}', status='{self.status}')>"
