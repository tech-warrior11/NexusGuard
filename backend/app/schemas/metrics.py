"""
Pydantic Schemas for Executive SOC Dashboard Metrics
"""
from typing import List, Dict, Any
from pydantic import BaseModel


class SeverityCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class AttackingIPStat(BaseModel):
    ip: str
    count: int
    threat_score: float
    country: str
    isp: str
    reputation: str


class MITREDistribution(BaseModel):
    tactic: str
    count: int
    technique_ids: List[str]


class TimelinePoint(BaseModel):
    time_label: str
    logs_count: int
    alerts_count: int


class SOCMetricsResponse(BaseModel):
    total_logs_ingested: int
    total_alerts: int
    active_open_alerts: int
    critical_alerts: int
    open_incidents: int
    threat_level: str               # DEFCON-1 (CRITICAL), ELEVATED, GUARDED, LOW
    threat_index_score: float       # 0 - 100
    severity_breakdown: SeverityCount
    top_attacking_ips: List[AttackingIPStat]
    mitre_tactics_breakdown: List[MITREDistribution]
    event_type_distribution: Dict[str, int]
    log_sources_distribution: Dict[str, int]
    activity_timeline: List[TimelinePoint]
