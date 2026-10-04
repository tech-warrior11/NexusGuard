"""
Pydantic Schemas for Threat Intelligence queries (AbuseIPDB, VirusTotal, MITRE ATT&CK)
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ThreatIntelQuery(BaseModel):
    indicator: str = Field(..., description="IP, Domain, or Hash to query", examples=["185.220.101.5"])
    indicator_type: Optional[str] = Field(None, description="ip, domain, hash (auto-detected if None)")


class AbuseIPDBDetails(BaseModel):
    ip_address: str
    is_public: bool = True
    ip_version: int = 4
    is_whitelisted: bool = False
    abuse_confidence_score: int = Field(..., description="Score from 0 to 100")
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    usage_type: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    hostnames: List[str] = []
    is_tor: bool = False
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported_at: Optional[datetime] = None


class VirusTotalDetails(BaseModel):
    indicator: str
    indicator_type: str
    reputation: int = 0
    malicious_votes: int = 0
    suspicious_votes: int = 0
    harmless_votes: int = 0
    undetected_votes: int = 0
    total_engines: int = 70
    detection_ratio: str = "0/70"
    threat_classification: Optional[str] = None
    engine_verdicts: Dict[str, str] = {}
    sandbox_tags: List[str] = []


class ThreatIntelResponse(BaseModel):
    indicator: str
    indicator_type: str # ip, domain, hash_sha256, hash_md5
    threat_level: str   # CLEAN, LOW, SUSPICIOUS, HIGH, CRITICAL
    overall_confidence: float
    description: str
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    abuseipdb: Optional[AbuseIPDBDetails] = None
    virustotal: Optional[VirusTotalDetails] = None
    cached: bool = True
    queried_at: datetime
