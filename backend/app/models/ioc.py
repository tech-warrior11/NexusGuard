"""
SQLAlchemy Model for Threat Intelligence Indicators of Compromise (IOCs)
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from app.core.database import Base


class ThreatIOC(Base):
    __tablename__ = "threat_iocs"

    id = Column(Integer, primary_key=True, index=True)
    ioc_value = Column(String(255), unique=True, index=True, nullable=False) # IP, Domain, Hash
    ioc_type = Column(String(50), index=True, nullable=False)                # ip, domain, hash_sha256, hash_md5
    threat_type = Column(String(100), nullable=False)                        # C2_SERVER, TOR_EXIT_NODE, BRUTE_FORCE, RANSOMWARE, PHISHING, SCANNER
    severity = Column(String(20), default="HIGH")                            # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score = Column(Float, default=90.0)                           # 0-100%
    abuseipdb_reports = Column(Integer, default=0)
    virustotal_positives = Column(Integer, default=0)
    virustotal_total = Column(Integer, default=70)
    country = Column(String(50), nullable=True)
    isp = Column(String(100), nullable=True)
    mitre_technique = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<ThreatIOC(value='{self.ioc_value}', type='{self.ioc_type}', score={self.confidence_score})>"
