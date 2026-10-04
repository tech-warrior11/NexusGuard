"""
Pydantic Schemas for Security Alert Ingestion, Updating, and Retrieval
"""
from datetime import datetime, timezone
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class AlertBase(BaseModel):
    alert_type: str = Field(..., description="Alert classification type (BRUTE_FORCE, REPEATED_FAILED_LOGIN, PRIVILEGE_ESCALATION, PORT_SCAN, THREAT_INTEL_IOC, etc.)")
    severity: str = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    source_ip: Optional[str] = Field(None, description="Source IP associated with alert")
    destination_ip: Optional[str] = Field(None, description="Target destination IP")
    username: Optional[str] = Field(None, description="Target username")
    description: str = Field(..., description="Detailed alert summary")
    rule_id: str = Field(..., description="Detection Rule ID that triggered this alert (e.g. RULE-001)")
    status: str = Field(default="OPEN", description="Alert Status: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    mitre_technique_id: Optional[str] = Field(None, description="MITRE ATT&CK Technique ID (e.g. T1110)")
    mitre_technique_name: Optional[str] = Field(None, description="MITRE Technique Name")
    mitre_tactic: Optional[str] = Field(None, description="MITRE Tactic category")
    ioc_value: Optional[str] = Field(None, description="Associated indicator of compromise")
    ioc_type: Optional[str] = Field(None, description="IOC type: ip, domain, hash_sha256")
    threat_score: Optional[float] = Field(0.0, description="Threat reputation / confidence score (0-100)")
    raw_event_data: Optional[str] = Field(None, description="Raw event context data")


class AlertCreate(AlertBase):
    timestamp: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))


class AlertUpdate(BaseModel):
    status: Optional[str] = Field(None, description="Updated status: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    description: Optional[str] = Field(None, description="Updated notes / description")


class AlertEscalateRequest(BaseModel):
    assigned_to: Optional[str] = Field("soc_analyst", description="Analyst to assign incident to")
    initial_notes: Optional[str] = Field(None, description="Initial triage investigation notes")


class AlertResponse(AlertBase):
    id: int
    timestamp: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertListResponse(BaseModel):
    total: int
    open_count: int
    investigating_count: int
    critical_count: int
    high_count: int
    alerts: List[AlertResponse]
