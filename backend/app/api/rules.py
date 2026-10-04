"""
Detection Rules Management API Endpoints
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.rule import DetectionRuleModel
from app.schemas.rule import DetectionRuleResponse, DetectionRuleListResponse, DetectionRuleUpdate

router = APIRouter(
    prefix="/rules",
    tags=["Detection Rules & Engine Tuning"]
)


@router.get("", response_model=DetectionRuleListResponse)
def get_detection_rules(
    db: Session = Depends(get_db)
):
    """
    List all detection rules configured in NexusGuard, their MITRE mapping, and trigger metrics.
    """
    rules = db.query(DetectionRuleModel).all()
    active_count = sum(1 for r in rules if r.enabled)

    return {
        "total": len(rules),
        "active_count": active_count,
        "rules": rules
    }


@router.get("/{rule_id}", response_model=DetectionRuleResponse)
def get_rule_by_id(
    rule_id: str,
    db: Session = Depends(get_db)
):
    """
    Get detailed configuration of a specific detection rule.
    """
    rule = db.query(DetectionRuleModel).filter(DetectionRuleModel.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found."
        )
    return rule


@router.patch("/{rule_id}", response_model=DetectionRuleResponse)
def update_detection_rule(
    rule_id: str,
    rule_update: DetectionRuleUpdate,
    db: Session = Depends(get_db)
):
    """
    Toggle enable/disable or tune threshold/window for a detection rule.
    """
    rule = db.query(DetectionRuleModel).filter(DetectionRuleModel.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found."
        )

    for field, value in rule_update.model_dump(exclude_unset=True).items():
        if value is not None:
            if field == "severity":
                setattr(rule, field, value.upper())
            else:
                setattr(rule, field, value)

    db.commit()
    db.refresh(rule)
    return rule


@router.post("/{rule_id}/toggle", response_model=DetectionRuleResponse)
def toggle_rule_status(
    rule_id: str,
    db: Session = Depends(get_db)
):
    """
    Quick toggle to enable or disable a detection rule.
    """
    rule = db.query(DetectionRuleModel).filter(DetectionRuleModel.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found."
        )

    rule.enabled = not rule.enabled
    db.commit()
    db.refresh(rule)
    return rule
