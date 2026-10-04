"""
SQLAlchemy Model for Security Incident Management, SOC Triage and Investigation Reports
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_number = Column(String(50), unique=True, index=True, nullable=False) # e.g., INC-2026-0001
    alert_id = Column(Integer, ForeignKey("alerts.id"), unique=True, nullable=True)
    title = Column(String(250), nullable=False)
    severity = Column(String(20), index=True, nullable=False)    # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(30), default="OPEN", index=True)      # OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    assigned_to = Column(String(100), nullable=True)             # SOC Analyst name
    summary = Column(Text, nullable=True)
    investigation_notes = Column(Text, nullable=True)
    mitre_tactics = Column(String(255), nullable=True)           # e.g., Initial Access, Credential Access
    mitre_techniques = Column(String(255), nullable=True)        # e.g., T1110, T1059.001
    iocs = Column(Text, nullable=True)                           # JSON array of IOCs (IPs, Hashes, Domains)
    containment_steps = Column(Text, nullable=True)              # Containment actions taken
    remediation_notes = Column(Text, nullable=True)              # Long-term remediation advice
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationship back to Alert
    alert = relationship("Alert", back_populates="incident")

    def __repr__(self):
        return f"<Incident(id={self.id}, number='{self.incident_number}', title='{self.title}', status='{self.status}', severity='{self.severity}')>"
