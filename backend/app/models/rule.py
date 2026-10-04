"""
SQLAlchemy Model for SOC Detection Rules
"""
from sqlalchemy import Column, Integer, String, Boolean, Text
from app.core.database import Base


class DetectionRuleModel(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g., RULE-001
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    enabled = Column(Boolean, default=True, nullable=False)
    rule_type = Column(String(50), nullable=False) # threshold, sequence, anomaly, signature, threat_intel
    mitre_technique_id = Column(String(50), nullable=True)   # T1110, T1046, T1059.001, etc.
    mitre_technique_name = Column(String(150), nullable=True) # Brute Force, Network Service Scanning, etc.
    mitre_tactic = Column(String(100), nullable=True)        # Credential Access, Discovery, Execution, etc.
    threshold = Column(Integer, default=5)                   # Count threshold within window
    time_window = Column(Integer, default=300)               # Time window in seconds (e.g., 300s = 5m)
    trigger_count = Column(Integer, default=0)               # Number of times rule has fired

    def __repr__(self):
        return f"<DetectionRuleModel(rule_id='{self.rule_id}', name='{self.name}', enabled={self.enabled}, triggers={self.trigger_count})>"
