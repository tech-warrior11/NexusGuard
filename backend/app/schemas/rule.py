"""
Pydantic Schemas for Detection Rule Configuration and Management
"""
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class DetectionRuleBase(BaseModel):
    rule_id: str
    name: str
    description: str
    severity: str
    enabled: bool = True
    rule_type: str
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    threshold: int = 5
    time_window: int = 300


class DetectionRuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    severity: Optional[str] = None
    threshold: Optional[int] = None
    time_window: Optional[int] = None
    description: Optional[str] = None


class DetectionRuleResponse(DetectionRuleBase):
    id: int
    trigger_count: int

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleListResponse(BaseModel):
    total: int
    active_count: int
    rules: List[DetectionRuleResponse]
