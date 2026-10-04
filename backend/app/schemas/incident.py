"""
Pydantic Schemas for SOC Incident Management, Investigation, and Reporting
"""
from datetime import datetime, timezone
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.alert import AlertResponse


class IncidentBase(BaseModel):
    title: str = Field(..., description="Incident title summary")
    severity: str = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    status: str = Field(default="OPEN", description="Status: OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE")
    assigned_to: Optional[str] = Field("soc_analyst", description="Assigned SOC Analyst")
    summary: Optional[str] = Field(None, description="Executive Summary of Incident")
    investigation_notes: Optional[str] = Field(None, description="Analyst Investigation Log / Evidence Notes")
    mitre_tactics: Optional[str] = Field(None, description="Comma separated MITRE tactics")
    mitre_techniques: Optional[str] = Field(None, description="Comma separated MITRE techniques")
    iocs: Optional[str] = Field(None, description="Associated IOC list in JSON string")
    containment_steps: Optional[str] = Field(None, description="Containment actions taken")
    remediation_notes: Optional[str] = Field(None, description="Recommended remediation / hardening")


class IncidentCreate(IncidentBase):
    alert_id: Optional[int] = Field(None, description="Source Alert ID if escalated from alert")
    incident_number: Optional[str] = Field(None, description="Auto-generated if empty")


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    summary: Optional[str] = None
    investigation_notes: Optional[str] = None
    mitre_tactics: Optional[str] = None
    mitre_techniques: Optional[str] = None
    iocs: Optional[str] = None
    containment_steps: Optional[str] = None
    remediation_notes: Optional[str] = None


class IncidentResponse(IncidentBase):
    id: int
    incident_number: str
    alert_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    alert: Optional[AlertResponse] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentListResponse(BaseModel):
    total: int
    open_count: int
    contained_count: int
    resolved_count: int
    incidents: List[IncidentResponse]


class IncidentReportResponse(BaseModel):
    incident_number: str
    title: str
    severity: str
    status: str
    assigned_to: Optional[str]
    created_at: datetime
    updated_at: datetime
    markdown_report: str
    html_report: str
