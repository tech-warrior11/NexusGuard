"""
Pydantic Schemas for Attack Simulator and Lab Scenarios
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ScenarioRunRequest(BaseModel):
    scenario_id: str = Field(..., description="Scenario: brute_force, port_scan, c2_beacon, powershell_obfuscated, windows_auth_chain, ransomware_hash, live_stream", examples=["brute_force"])
    target_ip: Optional[str] = Field("10.0.0.15", description="Target victim IP")
    attacker_ip: Optional[str] = Field("194.26.29.112", description="Attacker source IP")
    iterations: Optional[int] = Field(6, description="Number of events/attempts to simulate")


class ScenarioStepLog(BaseModel):
    step: int
    action: str
    log_source: str
    status: str
    details: str


class ScenarioRunResponse(BaseModel):
    scenario_id: str
    title: str
    description: str
    mitre_technique: str
    mitre_tactic: str
    logs_generated: int
    alerts_triggered: int
    alert_ids: List[int]
    investigation_steps: List[str]
    remediation_recommendations: List[str]
    sample_logs: List[ScenarioStepLog]
