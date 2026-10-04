"""
Pydantic Schemas for Security Log Ingestion, Normalization, and Querying
"""
from datetime import datetime, timezone
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class LogBase(BaseModel):
    source: str = Field(..., description="Log source: linux, windows, network, firewall, web, auth, endpoint", examples=["linux"])
    event_type: str = Field(..., description="Event type: authentication, network_scan, privilege_escalation, powershell_exec, logon_4625", examples=["authentication"])
    username: Optional[str] = Field(None, description="Target or executing username", examples=["admin"])
    source_ip: Optional[str] = Field(None, description="Source IPv4 or IPv6 address", examples=["192.168.1.50"])
    destination_ip: Optional[str] = Field(None, description="Destination IPv4 or IPv6 address", examples=["10.0.0.1"])
    port: Optional[int] = Field(None, description="Destination network port", examples=[22])
    protocol: Optional[str] = Field(None, description="Network protocol: TCP, UDP, ICMP, HTTP, SSH, RDP", examples=["TCP"])
    action: Optional[str] = Field(None, description="Action taken: login, connect, sudo, file_read, execute, scan", examples=["login"])
    status: str = Field(..., description="Event status: success, failed, denied, error, blocked, detected", examples=["failed"])
    message: Optional[str] = Field(None, description="Human readable log description", examples=["Failed SSH login attempt for root"])
    raw_payload: Optional[str] = Field(None, description="Raw event/packet/XML payload")


class LogCreate(LogBase):
    timestamp: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO-8601 timestamp of when the event occurred"
    )


class RawLogIngestRequest(BaseModel):
    format: str = Field(..., description="Format: raw_text, linux_auth, windows_event, json, pcap_stream", examples=["linux_auth"])
    content: str = Field(..., description="Raw text log line or XML snippet to be parsed and ingested")
    source: Optional[str] = Field(None, description="Optional override source")


class LogResponse(LogBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class LogListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    logs: List[LogResponse]
