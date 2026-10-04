"""
SOC Incident Response & Investigation Workbench API Endpoints
"""
from typing import Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.incident import Incident
from app.models.alert import Alert
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    IncidentListResponse,
    IncidentReportResponse
)
from app.services.incident_report import generate_incident_report

router = APIRouter(
    prefix="/incidents",
    tags=["Incident Response Workbench"]
)


@router.get("", response_model=IncidentListResponse)
def get_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned analyst"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """
    List SOC Incident Cases with filtering and status summary statistics.
    """
    query = db.query(Incident)

    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if status_filter:
        query = query.filter(Incident.status == status_filter.upper())
    if assigned_to:
        query = query.filter(Incident.assigned_to == assigned_to)

    total = query.count()
    incidents = query.order_by(desc(Incident.created_at)).offset(offset).limit(limit).all()

    open_count = db.query(Incident).filter(Incident.status == "OPEN").count()
    contained_count = db.query(Incident).filter(Incident.status == "CONTAINED").count()
    resolved_count = db.query(Incident).filter(Incident.status == "RESOLVED").count()

    return {
        "total": total,
        "open_count": open_count,
        "contained_count": contained_count,
        "resolved_count": resolved_count,
        "incidents": incidents
    }


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    inc_in: IncidentCreate,
    db: Session = Depends(get_db)
):
    """
    Manually create a new Incident Case.
    """
    # Auto-generate incident number if not provided
    if not inc_in.incident_number:
        count = db.query(Incident).count() + 1
        year = datetime.now(timezone.utc).year
        incident_num = f"INC-{year}-{count:04d}"
    else:
        incident_num = inc_in.incident_number

    incident = Incident(
        incident_number=incident_num,
        alert_id=inc_in.alert_id,
        title=inc_in.title,
        severity=inc_in.severity.upper(),
        status=inc_in.status.upper(),
        assigned_to=inc_in.assigned_to or "soc_analyst",
        summary=inc_in.summary,
        investigation_notes=inc_in.investigation_notes,
        mitre_tactics=inc_in.mitre_tactics,
        mitre_techniques=inc_in.mitre_techniques,
        iocs=inc_in.iocs,
        containment_steps=inc_in.containment_steps,
        remediation_notes=inc_in.remediation_notes
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident_by_id(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Retrieve full incident details including linked Alert, notes, and MITRE mapping.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found."
        )
    return incident


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    inc_update: IncidentUpdate,
    db: Session = Depends(get_db)
):
    """
    Update incident investigation details, status (CONTAINED/RESOLVED), containment steps, and analyst notes.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found."
        )

    for field, value in inc_update.model_dump(exclude_unset=True).items():
        if field == "status" and value:
            setattr(incident, field, value.upper())
        elif field == "severity" and value:
            setattr(incident, field, value.upper())
        else:
            setattr(incident, field, value)

    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}/report", response_model=IncidentReportResponse)
def get_incident_investigation_report(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Generate and download a comprehensive, professional Incident Response Investigation Report in Markdown & HTML.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found."
        )

    return generate_incident_report(incident)
